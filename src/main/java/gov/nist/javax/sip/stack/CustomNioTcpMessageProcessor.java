package gov.nist.javax.sip.stack;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.channels.SocketChannel;

/**
 * 自定义 NIO TCP 消息处理器，由
 * {@code com.genersoft.iot.vmp.gb28181.conf.CustomMessageProcessorFactory} 装配
 * （见 {@code gov.nist.javax.sip.MESSAGE_PROCESSOR_FACTORY} 配置）。
 *
 * <p><b>这里刻意不覆写 {@code createMessageChannel}，两个重载都不覆写。</b>
 *
 * <p>此类原先把 {@code createMessageChannel(HostPort)} 与
 * {@code createMessageChannel(InetAddress, int)} 都覆写成「只查 {@code messageChannels}
 * 缓存，查不到就返回 {@code null}」，意图是省掉建连开销。但父类
 * {@link NioTcpMessageProcessor} 的这两个重载本身就是「先查缓存，未命中则
 * {@code constructMessageChannel(...)} 建连并回填缓存」——
 * 覆写恰好把「未命中建连」这一段整个丢掉了，于是<b>任何尚未建过连接的出站 TCP 目标
 * 都拿不到通道</b>，对外表现为
 * {@code Could not create a message channel for <host>:<port>/TCP}。
 *
 * <p>症状很有迷惑性：对端主动连进来时，入站通道会以
 * {@code <对端IP>:<对端源端口>/TCP} 为 key 进缓存，出站恰好能命中它，于是
 * 「对端连着我时一切正常」；一旦这条连接断开、或对端换用其它源端口，出站立刻全线失败。
 * 表现为注册能过、心跳/目录/点播却说「发不出去」，很容易被怀疑到对端或网络。
 *
 * <p>需要在 TCP 侧追加自定义行为时，请<b>在委派给 {@code super} 之外追加</b>
 * （例如先做日志、再做缓存探测，未命中一律走 {@code super}），不要在未命中时返回
 * {@code null}。
 *
 * <hr>
 *
 * <p><b>本类的第二个职责：修补 jain-sip 1.3.0-91 在「换 socket」路径上的丢包缺陷。</b>
 *
 * <p>缺陷的触发条件：缓存里那条到对端的 socket 已断（对端在每次 REGISTER 应答后就会关连接，
 * 于是每次重发 REGISTER 都会走到「换 socket」这条路），
 * {@link NioTcpMessageChannel#sendTCPMessage(byte[])} 于是：
 * <ol>
 *   <li>{@code NIOHandler.sendBytes(...)} → {@code openOutgoingConnection(...)} →
 *       {@code NioTcpMessageProcessor.blockingConnect(...)}：新建 socket、连上、
 *       {@code configureBlocking(false)}，入队
 *       {@code ChangeRequest(socket, REGISTER, OP_READ)} 并 <b>{@code selector.wakeup()}</b>；</li>
 *   <li>回到 {@code sendBytes}，走 {@code writeChunks(...)} → 本类的
 *       {@link #send(SocketChannel, byte[])} → 入队 {@code PendingData} +
 *       {@code ChangeRequest(socket, CHANGEOPS, OP_WRITE)} 并再次 {@code wakeup()}；</li>
 *   <li><b>直到这时</b> {@code sendTCPMessage} 才做
 *       {@code close(false,false)}（关旧 socket，是个系统调用）+ 替换
 *       {@code this.socketChannel} + {@code nioHandler.putMessageChannel(新socket, this)}。</li>
 * </ol>
 *
 * <p>第 1、2 步已经把 selector 线程叫醒了，而第 3 步给新 socket 建立映射还在后面 ——
 * selector 线程只要先跑到 {@code ProcessorTask.write(key)}，
 * {@code nioHandler.getMessageChannel(新socket)} 就返回 {@code null}，于是打
 * {@code Need to write something on nioTcpMessageChannel null} → {@code Dead socketChannel}，
 * 执行 {@code key.cancel()} 与 {@code pendingData.remove(socket)}：<b>这批字节被静默丢弃，
 * 一个字节都没上线</b>。而应用层毫无感知，{@code SipProviderImpl} 照样打
 * {@code done sending ... to hop}，WVP 只能等 2000ms 后报
 * {@code 注册失败: 消息超时未回复}。
 *
 * <p>这条竞态由「应用线程关旧 socket 的耗时」与「selector 线程被唤醒的时机」决定胜负，
 * 所以表现为同一段代码时好时坏（实测 7 次换 socket 只丢了 1 次）。
 *
 * <p>修补方式：覆写 {@link #send(SocketChannel, byte[])}，在把 socket 交给 selector 线程
 * <b>之前</b>先把 {@code channelMap} 补上。这样做的正确性有保证：
 * 本方法里先 {@code putMessageChannel}，随后 {@code super.send} 才
 * {@code changeRequests.add(...)}，而 {@code changeRequests} 是
 * {@code ConcurrentLinkedQueue} —— selector 线程 {@code poll()} 到这条
 * {@code ChangeRequest} 时，必然能看到前面那次 put（{@code channelMap} 本身是无锁
 * {@code HashMap}，正是靠这个队列建立 happens-before 才安全）。
 */
public class CustomNioTcpMessageProcessor extends NioTcpMessageProcessor {

    private static final Logger log = LoggerFactory.getLogger(CustomNioTcpMessageProcessor.class);

    public CustomNioTcpMessageProcessor(InetAddress ipAddress,
                                        SIPTransactionStack sipStack, int port) {
        super(ipAddress, sipStack, port);
    }

    /**
     * 把数据入队并唤醒 selector 线程之前，先确保该 socket 在
     * {@link NIOHandler} 的 {@code channelMap} 里有对应的
     * {@link NioTcpMessageChannel}，否则 selector 线程的写事件处理会认为这是个
     * 「死 socket」而取消 key，把刚入队的这批字节一起丢掉。
     *
     * @see CustomNioTcpMessageProcessor 类注释里的完整时序说明
     */
    @Override
    public void send(SocketChannel socketChannel, byte[] bytes) throws IOException {
        ensureChannelCached(socketChannel);
        super.send(socketChannel, bytes);
    }

    /**
     * 只在「该 socket 还没有通道，但 socket 本身是活的」时补建通道。
     *
     * <p>正常路径（首次建连、复用缓存连接、对端连入）里通道早就建好了，
     * 这里直接返回，不会新建任何对象；只有上述换 socket 的竞态窗口才会真正动手。
     *
     * <p>补建出来的通道只是个「占位」：随后 {@code sendTCPMessage} 会把
     * {@code channelMap} 里这条映射替换成应用线程本来要用的那个通道对象，
     * 占位对象随即变成可回收的垃圾，不会再被引用。
     */
    private void ensureChannelCached(SocketChannel socketChannel) {
        if (socketChannel == null) {
            return;
        }
        NIOHandler handler = this.nioHandler;
        if (handler == null || handler.getMessageChannel(socketChannel) != null) {
            return;
        }
        if (!socketChannel.isOpen() || !socketChannel.isConnected()) {
            // socket 真的已经死了，按原有逻辑交给 selector 线程回收
            return;
        }
        try {
            createMessageChannel(this, socketChannel);
            if (log.isDebugEnabled()) {
                log.debug("[NIO 补建通道] 出站前发现 socket 无对应通道（jain-sip 换 socket 竞态窗口），"
                        + "已补建：socket={}", socketChannel);
            }
        } catch (IOException e) {
            // 补建失败不阻断本次发送，退回原生行为
            log.warn("[NIO 补建通道] 失败，本次发送可能丢失：socket={}, 原因={}", socketChannel, e.getMessage());
        }
    }
}
