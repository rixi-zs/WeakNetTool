#include "../src/weaknet_core.cpp"

#include <cstdio>

using namespace weaknet;

#define CHECK(expr) do { if (!(expr)) { \
    std::fprintf(stderr, "check failed at line %d: %s\n", __LINE__, #expr); \
    return 1; \
} } while (0)

int main()
{
    // 频率为 10 MHz 时，QPC 长时间运行也不能在乘 1000000 时溢出。
    CHECK(QpcTicksToUs(864000000000ULL, 10000000ULL) == 86400000000ULL);
    CHECK(QpcTicksToUs(ULLONG_MAX, 10000000ULL) ==
           (ULLONG_MAX / 10000000ULL) * 1000000ULL +
           ((ULLONG_MAX % 10000000ULL) * 1000000ULL) / 10000000ULL);
    CHECK(QpcTicksToUs(100, 0) == 0);

    // 进程模式的端口匹配应区分地址族和传输协议。
    CHECK(ProcessPortKey(4, IPPROTO_TCP, 443) != ProcessPortKey(4, IPPROTO_UDP, 443));
    CHECK(ProcessPortKey(4, IPPROTO_TCP, 443) != ProcessPortKey(6, IPPROTO_TCP, 443));

    // 只有一个包的令牌时，下一轮必须优先发送上轮未轮到的连接。
    ShapeQueue q;
    ShapeConfigureQueue(q, 1000000, 1000, 0);
    q.tokens = 1.0;
    q.lastRefillUs = 1000000ULL;
    FlowKey a = {};
    FlowKey b = {};
    a.srcPort = 1001;
    b.srcPort = 1002;
    for (int i = 0; i < 3; ++i) {
        ShapedPacket p;
        p.len = 1;
        p.charge = 1;
        p.enqueueUs = 1000000ULL;
        q.flows[a].packets.push_back(p);
    }
    ShapedPacket p;
    p.len = 1;
    p.charge = 1;
    p.enqueueUs = 1000000ULL;
    q.flows[b].packets.push_back(p);
    q.order.push_back(a);
    q.order.push_back(b);
    q.queuedBytes = 4;
    std::vector<ShapedPacket> out;
    ShapeCollectLocked(q, 1000000ULL, out);
    CHECK(out.size() == 1 && q.flows.find(b) != q.flows.end());
    CHECK(!q.order.empty() && q.order.front().srcPort == b.srcPort);
    q.tokens = 1.0;
    out.clear();
    ShapeCollectLocked(q, 1000000ULL, out);
    CHECK(out.size() == 1 && q.flows.find(b) == q.flows.end());

    // 全部过期后要清空轮询键，后续连接不会背负旧队列。
    ShapeQueue expired;
    ShapeConfigureQueue(expired, 1000, 10, 0);
    expired.flows[a].packets.push_back(p);
    expired.flows[a].bytes = 1;
    expired.queuedBytes = 1;
    expired.order.push_back(a);
    out.clear();
    ShapeCollectLocked(expired, 2000000ULL, out);
    CHECK(expired.flows.empty() && expired.order.empty() && expired.queuedBytes == 0);

    // 注入驱动打开、限速事件、限速线程、收包线程失败；整个启动必须失败且完成收尾。
    Config cfg;
    cfg.allPorts = true;
    cfg.installConsoleHandler = false;
    cfg.lossDownPercent = 0;
    cfg.lossUpPercent = 0;
    cfg.rateDownBytesPerSec = 1000;
    g_testFakeDriver = 1;
    for (int fault = 0; fault < 4; ++fault) {
        g_testFailDriverOpen = (fault == 0);
        g_testFailShapeEvent = (fault == 1);
        g_testFailShapeThread = (fault == 2);
        g_testFailWorkerThread = (fault == 3);
        Session session;
        const StartResult result = session.Start(cfg, NULL, NULL);
        CHECK(!result.ok);
        CHECK(LoadHandle() == NULL && g_workerThread == NULL && g_watcherThread == NULL);
        CHECK(g_shapeThread == NULL && g_shapeEvent == NULL);
        CHECK(g_stopEvent == NULL && g_finishedEvent == NULL);
    }
    g_testFailDriverOpen = 0;
    g_testFailShapeEvent = 0;
    g_testFailShapeThread = 0;
    g_testFailWorkerThread = 0;

    // 假驱动不触碰网络；反复启停仍应释放所有会话线程与事件。
    for (int cycle = 0; cycle < 20; ++cycle) {
        Session session;
        const StartResult result = session.Start(cfg, NULL, NULL);
        CHECK(result.ok);
        session.Stop();
        CHECK(LoadHandle() == NULL && g_workerThread == NULL && g_watcherThread == NULL);
        CHECK(g_shapeThread == NULL && g_shapeEvent == NULL && g_stopEvent == NULL);
    }
    g_testFakeDriver = 0;

    InterlockedExchange(const_cast<LONG*>(&g_stopReasonRaw), static_cast<LONG>(StopReason::None));
    InterlockedExchange(const_cast<LONG*>(&g_stopRequested), 0);
    RequestStop(StopReason::User);
    RequestStop(StopReason::Error);
    CHECK(GetStopReasonRaw() == StopReason::User);

    std::puts("weaknet_core_tests: algorithm, 4 failure paths, 20 start-stop cycles passed");
    return 0;
}
