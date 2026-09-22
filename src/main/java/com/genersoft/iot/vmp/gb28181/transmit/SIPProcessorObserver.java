package com.genersoft.iot.vmp.gb28181.transmit;

import com.genersoft.iot.vmp.gb28181.event.EventPublisher;
import com.genersoft.iot.vmp.gb28181.event.SipSubscribe;
import com.genersoft.iot.vmp.gb28181.event.sip.SipEvent;
import com.genersoft.iot.vmp.gb28181.transmit.event.request.ISIPRequestProcessor;
import com.genersoft.iot.vmp.gb28181.transmit.event.response.ISIPResponseProcessor;
import com.genersoft.iot.vmp.gb35114.sip.Gb35114NoteIntegrator;
import gov.nist.javax.sip.message.SIPResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import javax.sip.*;
import javax.sip.header.CSeqHeader;
import javax.sip.header.CallIdHeader;
import javax.sip.message.Request;
import javax.sip.message.Response;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @description: SIP信令处理类观察者
 * @author: panlinlin
 * @date:   2021年11月5日 下午15：32
 */
@Slf4j
@Component
public class SIPProcessorObserver implements ISIPProcessorObserver {

    private static final Map<String,  ISIPRequestProcessor> requestProcessorMap = new ConcurrentHashMap<>();
    private static final Map<String, ISIPResponseProcessor> responseProcessorMap = new ConcurrentHashMap<>();

    @Autowired
    private SipSubscribe sipSubscribe;

    @Autowired
    private EventPublisher eventPublisher;

    @Autowired
    private Gb35114NoteIntegrator gb35114NoteIntegrator;

    /**
     * 添加 request订阅
     * @param method 方法名
     * @param processor 处理程序
     */
    public void addRequestProcessor(String method, ISIPRequestProcessor processor) {
        requestProcessorMap.put(method, processor);
    }

    /**
     * 添加 response订阅
     * @param method 方法名
     * @param processor 处理程序
     */
    public void addResponseProcessor(String method, ISIPResponseProcessor processor) {
        responseProcessorMap.put(method, processor);
    }

    /**
     * 分发RequestEvent事件
     * @param requestEvent RequestEvent事件
     */
    @Override
    @Async
    public void processRequest(RequestEvent requestEvent) {
        Request request = requestEvent.getRequest();
        String method = request.getMethod();

        // GB35114 A 级：入站非 REGISTER 请求带 Note 头时先验签，失败回 403 并丢弃。
        if (!gb35114NoteIntegrator.verifyIncoming(request)) {
            log.warn("[GB35114] 丢弃 Note 验签失败的 {} 请求", method);
            try {
                javax.sip.message.Response forbidden =
                        SipFactory.getInstance().createMessageFactory()
                                .createResponse(Response.FORBIDDEN, request);
                if (requestEvent.getServerTransaction() != null) {
                    requestEvent.getServerTransaction().sendResponse(forbidden);
                }
            } catch (Exception e) {
                log.warn("[GB35114] 回 403 失败: {}", e.getMessage());
            }
            return;
        }

        ISIPRequestProcessor sipRequestProcessor = requestProcessorMap.get(method);
        if (sipRequestProcessor == null) {
            log.warn("不支持方法{}的request", method);
            // TODO 回复错误玛
            return;
        }
        requestProcessorMap.get(method).process(requestEvent);

    }

    /**
     * 分发ResponseEvent事件
     * @param responseEvent responseEvent事件
     */
    @Override
    @Async
    public void processResponse(ResponseEvent responseEvent) {
        SIPResponse response = (SIPResponse)responseEvent.getResponse();
        int status = response.getStatusCode();

        // Success
        if (((status >= Response.OK) && (status < Response.MULTIPLE_CHOICES)) || status == Response.UNAUTHORIZED) {
            ISIPResponseProcessor sipRequestProcessor = responseProcessorMap.get(response.getCSeqHeader().getMethod());
            if (sipRequestProcessor != null) {
                sipRequestProcessor.process(responseEvent);
            }

            CallIdHeader callIdHeader = response.getCallIdHeader();
            CSeqHeader cSeqHeader = response.getCSeqHeader();
            if (callIdHeader != null) {
                SipEvent sipEvent = sipSubscribe.getSubscribe(callIdHeader.getCallId() + cSeqHeader.getSeqNumber());
                if (sipEvent != null) {
                    if (sipEvent.getOkEvent() != null) {
                        SipSubscribe.EventResult<ResponseEvent> eventResult = new SipSubscribe.EventResult<>(responseEvent);
                        sipEvent.getOkEvent().response(eventResult);
                    }
                    sipSubscribe.removeSubscribe(callIdHeader.getCallId() + cSeqHeader.getSeqNumber());
                }
            }
        } else if ((status >= Response.TRYING) && (status < Response.OK)) {
            // 增加其它无需回复的响应，如101、180等
            // 更新sip订阅的时间
//            sipSubscribe.updateTimeout(response.getCallIdHeader().getCallId());
        } else {
            log.warn("接收到失败的response响应！status：" + status + ",message:" + response.getReasonPhrase());
            if (responseEvent.getResponse() != null && !sipSubscribe.isEmpty() ) {
                CallIdHeader callIdHeader = response.getCallIdHeader();
                CSeqHeader cSeqHeader = response.getCSeqHeader();
                if (callIdHeader != null) {
                    SipEvent sipEvent = sipSubscribe.getSubscribe(callIdHeader.getCallId() + cSeqHeader.getSeqNumber());
                    if (sipEvent != null ) {
                        if (sipEvent.getErrorEvent() != null) {
                            SipSubscribe.EventResult<ResponseEvent> eventResult = new SipSubscribe.EventResult<>(responseEvent);
                            sipEvent.getErrorEvent().response(eventResult);
                        }
                        sipSubscribe.removeSubscribe(callIdHeader.getCallId() + cSeqHeader.getSeqNumber());
                    }
                }
            }
            if (responseEvent.getDialog() != null) {
                responseEvent.getDialog().delete();
            }
        }


    }

    /**
     * 向超时订阅发送消息
     * @param timeoutEvent timeoutEvent事件
     */
    @Override
    public void processTimeout(TimeoutEvent timeoutEvent) {
        log.info("[消息发送超时]");
//        ClientTransaction clientTransaction = timeoutEvent.getClientTransaction();
//
//        if (clientTransaction != null) {
//            log.info("[发送错误订阅] clientTransaction != null");
//            Request request = clientTransaction.getRequest();
//            if (request != null) {
//                log.info("[发送错误订阅] request != null");
//                CallIdHeader callIdHeader = (CallIdHeader) request.getHeader(CallIdHeader.NAME);
//                if (callIdHeader != null) {
//                    log.info("[发送错误订阅]");
//                    SipSubscribe.Event subscribe = sipSubscribe.getErrorSubscribe(callIdHeader.getCallId());
//                    SipSubscribe.EventResult eventResult = new SipSubscribe.EventResult(timeoutEvent);
//                    if (subscribe != null){
//                        subscribe.response(eventResult);
//                    }
//                    sipSubscribe.removeOkSubscribe(callIdHeader.getCallId());
//                    sipSubscribe.removeErrorSubscribe(callIdHeader.getCallId());
//                }
//            }
//        }
//        eventPublisher.requestTimeOut(timeoutEvent);
    }

    @Override
    public void processIOException(IOExceptionEvent exceptionEvent) {
        System.out.println("processIOException");
    }

    @Override
    public void processTransactionTerminated(TransactionTerminatedEvent transactionTerminatedEvent) {
//        if (transactionTerminatedEvent.isServerTransaction()) {
//            ServerTransaction serverTransaction = transactionTerminatedEvent.getServerTransaction();
//            serverTransaction.get
//        }


//        Transaction transaction = null;
//        System.out.println("processTransactionTerminated");
//        if (transactionTerminatedEvent.isServerTransaction()) {
//            transaction = transactionTerminatedEvent.getServerTransaction();
//        }else {
//            transaction = transactionTerminatedEvent.getClientTransaction();
//        }
//
//        System.out.println(transaction.getBranchId());
//        System.out.println(transaction.getState());
//        System.out.println(transaction.getRequest().getMethod());
//        CallIdHeader header = (CallIdHeader)transaction.getRequest().getHeader(CallIdHeader.NAME);
//        SipSubscribe.EventResult<TransactionTerminatedEvent> terminatedEventEventResult = new SipSubscribe.EventResult<>(transactionTerminatedEvent);

//        sipSubscribe.getErrorSubscribe(header.getCallId()).response(terminatedEventEventResult);
    }

    @Override
    public void processDialogTerminated(DialogTerminatedEvent dialogTerminatedEvent) {
        CallIdHeader callId = dialogTerminatedEvent.getDialog().getCallId();
    }




}
