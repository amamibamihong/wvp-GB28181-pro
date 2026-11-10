package com.genersoft.iot.vmp.gb35114.cert.controller;

import com.genersoft.iot.vmp.conf.security.JwtUtils;
import com.genersoft.iot.vmp.gb35114.cert.bean.Gb35114Ca;
import com.genersoft.iot.vmp.gb35114.cert.bean.Gb35114Cert;
import com.genersoft.iot.vmp.gb35114.cert.service.IGb35114CertService;
import com.genersoft.iot.vmp.gb35114.conf.Gb35114Config;
import com.genersoft.iot.vmp.gb35114.sip.Gb35114SecurityService;
import com.genersoft.iot.vmp.vmanager.bean.WVPResult;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * GB35114 证书管理（web 界面）。
 *
 * <p>证书按类型分区管理：
 * <ul>
 *   <li><b>本地 CA</b>：本平台根 CA，私钥在本平台，用于签发；</li>
 *   <li><b>服务端证书（本平台）</b>：本平台作 UAS，签 sign2；</li>
 *   <li><b>客户端证书（本平台）</b>：本平台作 UAC，签 sign1；</li>
 *   <li><b>客户端证书（下级设备）</b>：签发给下级，私钥交付下级；</li>
 *   <li><b>服务端证书（上级平台）</b>：仅公钥，验 sign2。</li>
 * </ul>
 *
 * <p><b>私钥一律不通过接口下发</b>：本地身份证书的私钥与 CSR 存于同一条记录，
 * 仅在服务端签名时内部解密使用；删除记录即一并删除私钥。
 *
 * <p><b>接口文档通用约定</b>（下面各接口不再重复）：
 * <ul>
 *   <li>全部接口需登录，请求头带 {@code access-token}；</li>
 *   <li>{@code certFile} / {@code keyFile} 均为 <b>PEM 文本文件</b>（{@code multipart/form-data} 上传），
 *       不是二进制 DER；</li>
 *   <li>形如 {@code Gb35114Cert profile} 的参数<b>不是 JSON 请求体</b>，而是表单字段绑定 ——
 *       CN 与 DN 各段（C/ST/L/O/OU）按字段名提交即可；落库的各段一律由签出的证书反解析得到，
 *       不采信表单原值；</li>
 *   <li>{@code validityDays} 不传或传非正数时回退到配置 {@code gb35114.cert-validity-days}；</li>
 *   <li>创建、吊销、删除、绑定等<b>改变签名身份</b>的操作会同时丢弃 UAS/UAC 证书状态机缓存，
 *       下次注册按最新证书集重建 —— 否则会继续用旧私钥签 sign2，设备验签失败即拒绝对后续信令服务。</li>
 * </ul>
 */
@Tag(name = "GB35114 证书管理", description = "GB/T 35114 A 级国密接入的证书与 CA 管理。"
        + "证书按类型分区：本地根 CA（签发）、服务端证书（本平台，签 sign2）、"
        + "客户端证书（本平台，签 sign1）、客户端证书（下级设备）、服务端证书（上级平台，验 sign2）。"
        + "<br>私钥一律不通过任何接口下发。")
@Slf4j
@RestController
@RequestMapping("/api/gb35114/cert")
public class Gb35114CertController {

    /** 证书类型取值说明，多处复用，避免各接口各写一遍导致口径漂移。 */
    private static final String TYPE_DESC = "证书类型。SERVER_IDENTITY-服务端证书（本平台，作 UAS 签 sign2，私钥在本平台）；"
            + "DEVICE_IDENTITY-客户端证书（本平台，作 UAC 签 sign1，私钥在本平台，须上级签发）；"
            + "ISSUED_DEVICE-客户端证书（下级设备，私钥不在本平台）；"
            + "TRUSTED_PLATFORM-服务端证书（上级平台，仅公钥，用于验 sign2）";

    @Autowired
    private IGb35114CertService certService;

    /**
     * UAS 状态机持有签名身份与已协商的 VKEK。证书新增/吊销/删除/换发后必须丢弃
     * 缓存的状态机，否则会继续用旧私钥签 sign2 —— 设备验签失败即拒绝对后续信令服务。
     */
    @Autowired
    private Gb35114SecurityService gb35114SecurityService;

    @Autowired
    private Gb35114Config config;

    /**
     * 丢弃全部证书状态机缓存（UAS + UAC），下次注册时按最新证书集重建。
     *
     * <p>创建/吊销/删除服务端证书都会改变签名身份或使其不可用，缓存里的状态机若继续
     * 持有旧私钥签 sign2，设备验签失败即拒绝对后续信令服务。UAC 侧同理 ——
     * 级联用的客户端证书变了，向上注册的 sign1 也会用错身份。
     */
    private void resetPlatformStateMachines() {
        gb35114SecurityService.invalidateAllCertStateMachines();
    }

    /**
     * 证书相关策略（只读），供前端渲染策略感知的提示文案。
     *
     * <p>不返回任何私钥、加密口令或证书内容 —— 只有布尔与数值。
     */
    @Operation(summary = "查询证书策略（只读）",
            description = "返回影响证书行为的开关与参数，供前端渲染「策略感知」的提示文案。<ul>"
                    + "<li><b>rejectExpiredCert</b>：过期证书是否拒绝注册（默认 false）；</li>"
                    + "<li><b>verifyUpstreamCertChain</b>：本平台作下级时是否校验上级证书链（默认 true）；</li>"
                    + "<li><b>skipCertChainVerify</b>：是否全局跳过证书链校验（默认 false，仅拿不到 CA 时用）；</li>"
                    + "<li><b>certValidityDays</b>：默认有效期天数；</li>"
                    + "<li><b>moduleId</b>：证书主题里用的密码模块 ID（22 位数字），页面据此拼默认 CN。</li>"
                    + "</ul>"
                    + "只返回布尔与数值，不含任何私钥、口令或证书内容。",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
    @GetMapping("/policy")
    public WVPResult<Map<String, Object>> policy() {
        Map<String, Object> policy = new LinkedHashMap<>();
        // 过期证书是否拒绝注册：默认 false，页面据此决定提示是「已过期」还是「将被拒绝注册」
        policy.put("rejectExpiredCert", config.isRejectExpiredCert());
        // 本平台作下级时是否校验上级证书链：默认 true，页面据此提示「自签上级证书需同时作为受信任的 CA 导入」
        policy.put("verifyUpstreamCertChain", config.isVerifyUpstreamCertChain());
        // 是否跳过证书链签名验证：默认 false。页面据此提示「拿不到 CA 时可用，但会降低防护」
        policy.put("skipCertChainVerify", config.isSkipCertChainVerify());
        policy.put("certValidityDays", config.getCertValidityDays());
        // 主题里用的密码模块 ID（附录 A 表 A.1 / 附录 B，22 位数字）。页面用它拼默认主题
        // 「国标ID_密码模块ID」。空值时回默认的全 0，前端不必自己兜底。
        policy.put("moduleId", config.resolvedModuleId());
        return WVPResult.success(policy);
    }

    // ------------------------------------------------------------------
    // CA 管理
    // ------------------------------------------------------------------

    @Operation(summary = "生成本地根 CA",
            description = "生成 SM2 自签根 CA（type=LOCAL_CA），私钥加密留存本平台，用于签发各类证书。<br>"
                    + "<b>本地 CA 全局只保留一份</b>：已存在 LOCAL_CA 时直接拒绝，需先删除旧的"
                    + "（删除会被引用校验拦下 —— 仍被证书引用的 CA 删不掉）。"
                    + "受信任的 CA（TRUSTED_CA）不受此限制，多个上级平台各一份。<br>"
                    + "CA 没有独立的「名称」字段，它的身份就是证书的主题 CN：取自下方表单参数或证书本身，"
                    + "不由调用方另起别名。落库的 DN 各段一律由签出的证书反解析得到，不采信表单原值。",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
    @Parameter(name = "validityDays", description = "有效期天数。默认 0 —— 不传或非正数时回退到配置 gb35114.cert-validity-days")
    @PostMapping("/ca/generate")
    public WVPResult<Gb35114Ca> generateCa(Gb35114Ca profile,
                                           @RequestParam(defaultValue = "0") int validityDays) {
        return WVPResult.success(certService.generateCa(profile, validityDays));
    }

    @Operation(summary = "导入外部 CA（本地根CA需私钥，受信任的CA仅证书）",
            description = "导入由外部工具或上级签发的 CA 证书。<br>"
                    + "<b>type=LOCAL_CA</b>：必须同时上传私钥（keyFile），导入等价于新建，"
                    + "同样受「本地 CA 全局只保留一份」约束。<br>"
                    + "<b>type=TRUSTED_CA</b>：只需证书，仅保存公钥，用于校验对端证书链；"
                    + "可重复导入多份（多个上级、多家签发机构）。<br>"
                    + "现场常见的自签上级证书，需把<b>该证书本身</b>也作为 TRUSTED_CA 导入一份，"
                    + "否则开启上级证书链校验后级联注册会被拒。",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
    @Parameter(name = "type", description = "CA 类型。LOCAL_CA-本地根 CA（需私钥，全局唯一）；"
            + "TRUSTED_CA-受信任的 CA（仅证书，可多份）。不传时按 LOCAL_CA 处理")
    @Parameter(name = "remark", description = "备注")
    @Parameter(name = "certFile", description = "CA 证书 PEM 文本文件（必填）", required = true)
    @Parameter(name = "keyFile", description = "CA 私钥 PEM 文本文件。type=LOCAL_CA 时必填；TRUSTED_CA 不需要")
    @PostMapping("/ca/import")
    public WVPResult<Gb35114Ca> importCa(@RequestParam(required = false) String type,
                                         @RequestParam(required = false) String remark,
                                         @RequestParam("certFile") MultipartFile certFile,
                                         @RequestParam(value = "keyFile", required = false) MultipartFile keyFile) {
        String certPem;
        String keyPem;
        try {
            certPem = new String(certFile.getBytes(), StandardCharsets.UTF_8);
            keyPem = keyFile == null ? null : new String(keyFile.getBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("读取 CA 文件失败: " + e.getMessage(), e);
        }
        // 服务调用放在 try 之外：本地 CA 唯一性守卫、PEM 解析失败等都会抛出可读错误，
        // 套上「读取 CA 文件失败」的前缀只会把真正的原因埋掉。
        return WVPResult.success(certService.importCa(type, certPem, keyPem, remark));
    }

    @Operation(summary = "查询全部 CA",
            description = "返回全部 CA（不含私钥密文，只带 hasKey 表示本平台是否持有其私钥）。"
                    + "TRUSTED_CA 会附带其服务的上级平台名（瞬态字段 relatedPlatformName）。"
                    + "列表只带 certCount 一个张数，签发的证书清单按需另调「查询该 CA 签发的证书清单」。",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
    @Parameter(name = "type", description = "按类型过滤。LOCAL_CA-本地根 CA；TRUSTED_CA-受信任的 CA。不传则返回全部")
    @GetMapping("/ca/list")
    public WVPResult<List<Gb35114Ca>> listCa(@RequestParam(required = false) String type) {
        return WVPResult.success(type == null || type.isEmpty()
                ? certService.queryAllCa() : certService.queryCaByType(type));
    }

    @Operation(summary = "下载 CA 证书 PEM（交付对端导入，用于验签本平台证书）",
            description = "<b>返回 PEM 文本流，不是 JSON</b>，Swagger 上显示的响应体为空属正常。<br>"
                    + "响应头 <code>Content-Disposition: attachment; filename=&lt;主题CN&gt;.crt</code>。<br>"
                    + "CA 不存在或证书内容为空时返回 <b>204 No Content</b>。",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
    @Parameter(name = "id", description = "CA 的主键 ID", required = true)
    @GetMapping("/ca/download/{id}")
    public void downloadCa(HttpServletResponse resp, @PathVariable int id) {
        Gb35114Ca ca = certService.queryCa(id);
        writeText(resp, ca == null ? null : ca.getCertPem(),
                (ca == null || ca.getSubjectCn() == null ? "ca" : ca.getSubjectCn()) + ".crt");
    }

    @Operation(summary = "查询该 CA 签发的证书清单（CA 页面点开「关联证书」用）",
            description = "列出 ca_id 指向该 CA 的全部证书。列表接口只返回 certCount 一个数，"
                    + "清单按需单独拉 —— CA 多、证书多时把清单塞进列表响应会把响应撑大，而多数时候用户只看张数。",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
    @Parameter(name = "id", description = "CA 的主键 ID", required = true)
    @GetMapping("/ca/certs/{id}")
    public WVPResult<List<Gb35114Cert>> listCaCerts(@PathVariable int id) {
        return WVPResult.success(certService.queryCertsByCaId(id));
    }

    @Operation(summary = "删除 CA（被证书引用时拒绝）",
            description = "删除 CA。<b>仍被证书引用时拒绝</b>，并在错误信息里点名是哪些证书在占位 ——"
                    + "先处理掉那些证书（删除或改由别的 CA 签发）再删 CA。<br>"
                    + "删除本地根 CA 不会连带删除它签发的证书，那些证书会变成「签发者已不存在」。",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
    @Parameter(name = "id", description = "CA 的主键 ID", required = true)
    @DeleteMapping("/ca/delete/{id}")
    public WVPResult<?> deleteCa(@PathVariable int id) {
        certService.deleteCa(id);
        return WVPResult.success();
    }

    // ------------------------------------------------------------------
    // 本地身份证书（本平台持有私钥）
    // ------------------------------------------------------------------

    @Operation(summary = "一步创建服务端证书（本平台）：生成密钥对并当场签发；caId 为空则自签",
            description = "服务端证书最省事的一条创建路径（三步并作一步）。另外两条是"
                    + "「创建 CSR → 用本地 CA 签发」与「导入外部签发的证书 + 私钥」。<br>"
                    + "签发方式由 <b>caId</b> 决定：非空用该本地 CA 签发（其私钥须在本平台）；"
                    + "<b>为空则自签</b>（签发者即自身，无 CA 的联调环境可用）。两条路径都不建 CA 层级、"
                    + "都不需要外部参与，一次调用即可拿到可用证书。<br>"
                    + "仅限<b>服务端证书</b>：本平台作 UAS 用它签 sign2，设备侧只需拿到公钥，"
                    + "谁签的、是否自签都不影响验签。客户端证书必须由上级签发，调用会被拒绝。<br>"
                    + "<b>受「服务端只保留一组密钥对」约束</b>：已有服务端证书（未删除）时拒绝。"
                    + "换发路径是「先删除、再重新创建」—— 新证书是新的密钥对，"
                    + "绑定过旧证书的设备必须重新导入平台证书才能注册。<br>"
                    + "成功后丢弃证书状态机缓存。",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
    @Parameter(name = "caId", description = "签发用的本地 CA ID。<b>为空则自签</b>")
    @Parameter(name = "validityDays", description = "有效期天数，默认 3650；非正数时回退到配置 gb35114.cert-validity-days")
    @PostMapping("/server-identity/create")
    public WVPResult<Gb35114Cert> createServerIdentity(Gb35114Cert profile,
                                                       @RequestParam(required = false) Integer caId,
                                                       @RequestParam(defaultValue = "3650") int validityDays) {
        Gb35114Cert cert = certService.createServerIdentity(profile, caId, validityDays);
        resetPlatformStateMachines();
        return WVPResult.success(cert);
    }

    @Operation(summary = "创建证书请求（CSR）：生成密钥对并加密留存私钥；服务端证书可随后由本平台签发，"
            + "客户端证书（本平台）须交上级签发后回填",
            description = "生成 SM2 密钥对与 CSR，<b>私钥加密后与 CSR 存在同一条记录</b>，证书列留空等待签发。"
                    + "返回记录含 id 与 csrPem。<br>"
                    + "服务端证书（本平台）与客户端证书（本平台）都走这条路，区别在签发者：<ul>"
                    + "<li>服务端证书 —— 用「用本地 CA 签发待签发的服务端证书」在本平台完成，"
                    + "也可用「回填待签发记录」导入外部签发的证书；</li>"
                    + "<li>客户端证书 —— <b>只能</b>把 CSR 交给上级签发，再回填。"
                    + "本平台自签的证书上级那边没有记录，级联接入必被拒。</li></ul>"
                    + "类型为 SERVER_IDENTITY 时受「服务端只保留一组密钥对」约束。<br>"
                    + "创建后用「导出待签发记录的 CSR」取走 CSR。",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
    @Parameter(name = "validityDays", description = "期望的有效期天数，默认 3650（此处仅记录，实际以签发时为准）")
    @PostMapping("/csr/generate")
    public WVPResult<Gb35114Cert> generateCsr(Gb35114Cert profile,
                                              @RequestParam(defaultValue = "3650") int validityDays) {
        return WVPResult.success(certService.createPendingCsr(profile, validityDays));
    }

    @Operation(summary = "用本地 CA 签发待签发的服务端证书（caId 为空则自签）",
            description = "在本平台内完成签发并<b>原地回填</b>该待签发记录，私钥始终不出本平台。<br>"
                    + "与「回填待签发记录」并列：那条回填外部 CA 签发的证书，这条在本平台内完成。<br>"
                    + "<b>只接受服务端证书</b> —— 客户端证书必须由上级签发，调用会被拒绝。<br>"
                    + "成功后丢弃证书状态机缓存（服务端证书换了，状态机持有的还是旧身份）。",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
    @Parameter(name = "id", description = "待签发记录（CSR）的主键 ID", required = true)
    @Parameter(name = "caId", description = "签发用的本地 CA ID。<b>为空则自签</b>")
    @Parameter(name = "validityDays", description = "有效期天数，默认 3650；非正数时回退到配置 gb35114.cert-validity-days")
    @PostMapping("/csr/sign/{id}")
    public WVPResult<Gb35114Cert> signPending(@PathVariable int id,
                                              @RequestParam(required = false) Integer caId,
                                              @RequestParam(defaultValue = "3650") int validityDays) {
        Gb35114Cert cert = certService.signPendingServerIdentity(id, caId, validityDays);
        // 与 createServerIdentity 一致：服务端证书换了，状态机持有的还是旧身份
        resetPlatformStateMachines();
        return WVPResult.success(cert);
    }

    @Operation(summary = "用外部 CA 返回的证书回填待签发记录（校验公私钥配对）",
            description = "把上级或外部 CA 签回的证书填进已有待签发记录，与本地留存的私钥配成一对。<br>"
                    + "会<b>校验证书公钥与本地私钥匹配</b> —— 不匹配说明签回的不是这把密钥的证书，直接报错。<br>"
                    + "成功后丢弃证书状态机缓存（回填的同样可能是服务端证书，状态机持有的身份一样会过期）。",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
    @Parameter(name = "id", description = "待签发记录（CSR）的主键 ID", required = true)
    @Parameter(name = "certFile", description = "外部 CA 签回的证书 PEM 文本文件（必填）", required = true)
    @PostMapping("/csr/complete/{id}")
    public WVPResult<Gb35114Cert> completePending(@PathVariable int id,
                                                  @RequestParam("certFile") MultipartFile certFile) {
        try {
            String certPem = new String(certFile.getBytes(), StandardCharsets.UTF_8);
            Gb35114Cert cert = certService.completePendingWithCert(id, certPem);
            // 回填的同样可能是服务端证书，状态机持有的身份一样会过期
            resetPlatformStateMachines();
            return WVPResult.success(cert);
        } catch (Exception e) {
            throw new RuntimeException("读取证书文件失败: " + e.getMessage(), e);
        }
    }

    @Operation(summary = "导出待签发记录的 CSR（交付外部 CA）",
            description = "<b>返回 PEM 文本流，不是 JSON</b>，Swagger 上显示的响应体为空属正常。<br>"
                    + "响应头 <code>Content-Disposition: attachment; filename=&lt;国标ID&gt;.csr</code>。<br>"
                    + "该记录没有 CSR 时返回 <b>204 No Content</b>。",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
    @Parameter(name = "id", description = "待签发记录（CSR）的主键 ID", required = true)
    @GetMapping("/csr/download/{id}")
    public void downloadCsr(HttpServletResponse resp, @PathVariable int id) {
        Gb35114Cert cert = certService.queryCert(id);
        String csrPem = cert == null ? null : cert.getCsrPem();
        if (csrPem == null || csrPem.isEmpty()) {
            resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
            return;
        }
        writeText(resp, csrPem, (cert.getGbId() == null ? "request" : cert.getGbId()) + ".csr");
    }

    @Operation(summary = "导入本平台身份证书（证书 + 私钥，校验配对）",
            description = "用外部工具签发的证书 + 私钥，直接落一条可用记录（回填路径）。"
                    + "<b>会校验证书与私钥配对</b>，不匹配直接报错。<br>"
                    + "类型为服务端证书时受「服务端只保留一组密钥对」约束。<br>"
                    + "<b>私钥仅加密留存于本平台，不会通过任何接口下发</b>；删除该记录即一并删除私钥。",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
    @Parameter(name = "certFile", description = "证书 PEM 文本文件（必填）", required = true)
    @Parameter(name = "keyFile", description = "证书私钥 PEM 文本文件（必填），须与证书配对", required = true)
    @PostMapping("/import/identity")
    public WVPResult<Gb35114Cert> importIdentity(Gb35114Cert profile,
                                                 @RequestParam("certFile") MultipartFile certFile,
                                                 @RequestParam("keyFile") MultipartFile keyFile) {
        String certPem;
        String keyPem;
        try {
            certPem = new String(certFile.getBytes(), StandardCharsets.UTF_8);
            keyPem = new String(keyFile.getBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("读取证书文件失败: " + e.getMessage(), e);
        }
        // 服务调用放在 try 之外：它自己会抛出可读的校验错误（密钥对守卫、证书与私钥不匹配等），
        // 套上「读取证书文件失败」的前缀只会把真正的原因埋掉。
        return WVPResult.success(certService.importIdentityCert(profile, certPem, keyPem));
    }

    // ------------------------------------------------------------------
    // 下级 / 上级对端证书
    // ------------------------------------------------------------------

    @Operation(summary = "由下级提交的 CSR 签发证书（私钥留在下级）",
            description = "本平台作 UAS 时给下级设备/平台签发客户端证书（type 固定 ISSUED_DEVICE）。"
                    + "<b>私钥始终留在下级</b>，本平台只落签出的证书，不存私钥。<br>"
                    + "签发后需把本平台 CA 证书交给下级导入，下级才验得过本平台签的 sign2。",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
    @Parameter(name = "caId", description = "签发用的本地 CA ID（必填，不能自签）", required = true)
    @Parameter(name = "gbId", description = "下级国标编码。<b>为空时从 CSR 主题 CN 中提取</b>")
    @Parameter(name = "remark", description = "备注")
    @Parameter(name = "csrPem", description = "下级提交的 CSR 内容（PEM 字符串，直接传文本，不是文件上传）", required = true)
    @Parameter(name = "validityDays", description = "有效期天数，默认 3650；非正数时回退到配置 gb35114.cert-validity-days")
    @Parameter(name = "keyUsage", description = "密钥用途扩展描述串，如 digitalSignature、keyCertSign|cRLSign。"
            + "为空时默认 digitalSignature")
    @PostMapping("/issue/csr")
    public WVPResult<Gb35114Cert> issueFromCsr(@RequestParam int caId,
                                               @RequestParam(required = false) String gbId,
                                               @RequestParam(required = false) String remark,
                                               @RequestParam String csrPem,
                                               @RequestParam(defaultValue = "3650") int validityDays,
                                               @RequestParam(required = false) String keyUsage) {
        return WVPResult.success(certService.issueFromExternalCsr(
                caId, gbId, remark, csrPem, validityDays, keyUsage));
    }

    @Operation(summary = "同一份下级 CSR 再次签发（续期/补发，复用原记录与国标 ID）",
            description = "用于证书续期或补发。<b>CSR 已在本平台留存时复用原记录</b>，新证书写入该记录"
                    + "（保持同一个国标 ID 与绑定关系）；找不到留存记录时退化为新建一条，"
                    + "等同于「由下级提交的 CSR 签发证书」。<br>"
                    + "参数含义与「由下级提交的 CSR 签发证书」完全一致。",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
    @Parameter(name = "caId", description = "签发用的本地 CA ID（必填）", required = true)
    @Parameter(name = "gbId", description = "下级国标编码。为空时从 CSR 主题 CN 中提取")
    @Parameter(name = "remark", description = "备注")
    @Parameter(name = "csrPem", description = "下级提交的 CSR 内容（PEM 字符串）", required = true)
    @Parameter(name = "validityDays", description = "有效期天数，默认 3650；非正数时回退到配置 gb35114.cert-validity-days")
    @Parameter(name = "keyUsage", description = "密钥用途扩展描述串。为空时默认 digitalSignature")
    @PostMapping("/issue/csr/reissue")
    public WVPResult<Gb35114Cert> reissueFromCsr(@RequestParam int caId,
                                                 @RequestParam(required = false) String gbId,
                                                 @RequestParam(required = false) String remark,
                                                 @RequestParam String csrPem,
                                                 @RequestParam(defaultValue = "3650") int validityDays,
                                                 @RequestParam(required = false) String keyUsage) {
        return WVPResult.success(certService.reissueFromCsr(
                caId, gbId, remark, csrPem, validityDays, keyUsage));
    }

    @Operation(summary = "导入对端证书（仅公钥：服务端证书（上级平台） / 客户端证书（下级设备））",
            description = "导入对端的证书，<b>仅保存公钥，不落私钥</b>。<ul>"
                    + "<li>type=TRUSTED_PLATFORM —— 上级平台的服务端证书，用于验上级下发的 sign2；</li>"
                    + "<li>type=ISSUED_DEVICE —— 下级设备的客户端证书，用于验设备上报的 sign1。"
                    + "外部 CA 签发的设备证书必须先经此接口导入本平台保存，"
                    + "否则设备接入时会被拒（A 级握手不校验证书链，自签证书也验得过，"
                    + "「本平台保存且有效」是接入的前提）。</li></ul>"
                    + "导入时会尝试解析签发者是否已导入本平台，未导入则返回 importWarning 提示（不阻断）。",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
    @Parameter(name = "certFile", description = "对端证书 PEM 文本文件（必填，仅证书，不要传私钥）", required = true)
    @PostMapping("/import/peer")
    public WVPResult<Gb35114Cert> importPeer(Gb35114Cert profile,
                                             @RequestParam("certFile") MultipartFile certFile) {
        try {
            String certPem = new String(certFile.getBytes(), StandardCharsets.UTF_8);
            return WVPResult.success(certService.importPeerCert(profile, certPem));
        } catch (Exception e) {
            throw new RuntimeException("读取证书文件失败: " + e.getMessage(), e);
        }
    }

    // ------------------------------------------------------------------
    // 查询 / 下载证书 / 吊销 / 删除
    // ------------------------------------------------------------------

    @Operation(summary = "查询证书列表（不含私钥）",
            description = "返回证书列表。<b>响应不含私钥</b>，只有布尔字段 hasKey 表示本平台是否持有其私钥。<br>"
                    + "每条记录还带几个瞬态字段供页面渲染：issuerDn/selfSigned（签发者与是否自签，"
                    + "每次查询按 certPem 现算）、relatedDeviceId/relatedDeviceName 与 "
                    + "relatedPlatformId/relatedPlatformName（该证书当前被哪个设备/级联平台引用）。",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
    @Parameter(name = "type", description = "按类型过滤。" + TYPE_DESC + "。不传则返回全部")
    @GetMapping("/list")
    public WVPResult<List<Gb35114Cert>> list(@RequestParam(required = false) String type) {
        return WVPResult.success(type == null || type.isEmpty()
                ? certService.queryAllCerts() : certService.queryCertsByType(type));
    }

    @Operation(summary = "按国标 ID 查询证书",
            description = "返回 gb_id 等于该值的全部证书（可能多张：同一台设备换发过证书、"
                    + "或同一国标 ID 下并存不同用途的证书）。",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
    @Parameter(name = "gbId", description = "国标编码（设备编号或平台编号，20 位）", required = true)
    @GetMapping("/list/{gbId}")
    public WVPResult<List<Gb35114Cert>> listByGbId(@PathVariable String gbId) {
        return WVPResult.success(certService.queryByGbId(gbId));
    }

    @Operation(summary = "下载证书 PEM",
            description = "<b>返回 PEM 文本流，不是 JSON</b>，Swagger 上显示的响应体为空属正常。<br>"
                    + "响应头 <code>Content-Disposition: attachment; filename=&lt;国标ID&gt;.crt</code>。<br>"
                    + "证书不存在或内容为空时返回 <b>204 No Content</b>。<br>"
                    + "该接口只导出证书（公钥部分），<b>不会导出私钥</b>。",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
    @Parameter(name = "id", description = "证书的主键 ID", required = true)
    @GetMapping("/download/cert/{id}")
    public void downloadCert(HttpServletResponse resp, @PathVariable int id) {
        Gb35114Cert cert = certService.queryCert(id);
        writeText(resp, cert == null ? null : cert.getCertPem(),
                (cert == null || cert.getGbId() == null ? "cert" : cert.getGbId()) + ".crt");
    }

    @Operation(summary = "吊销证书",
            description = "把证书标记为已吊销。吊销是对该签名身份「停用」的明确指令 ——"
                    + "同一密钥对的证书共用私钥，一旦泄露必然整组一起吊销，"
                    + "因此解析可用证书时<b>不会顺延到同组的兄弟证书</b>（过期会顺延，吊销不会）。<br>"
                    + "吊销后丢弃证书状态机缓存。记录本身保留，可在列表里看到。",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
    @Parameter(name = "id", description = "证书的主键 ID", required = true)
    @PostMapping("/revoke/{id}")
    public WVPResult<?> revoke(@PathVariable int id) {
        certService.revokeCert(id);
        resetPlatformStateMachines();
        return WVPResult.success();
    }

    @Operation(summary = "删除证书（本地身份证书连同私钥一并删除；被设备/平台引用时拒绝）",
            description = "删除证书记录。本地身份证书的私钥与该记录同存，<b>删除记录即一并删除私钥</b>。<br>"
                    + "<b>仍被设备或级联平台引用时拒绝</b>并点名引用方 —— 需先解绑。"
                    + "若引用方是本级联平台的证书槽，用「删除证书并解除级联平台的绑定」；"
                    + "若是设备，先到设备配置里换掉证书。<br>"
                    + "删除后丢弃证书状态机缓存。",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
    @Parameter(name = "id", description = "证书的主键 ID", required = true)
    @DeleteMapping("/delete/{id}")
    public WVPResult<?> delete(@PathVariable int id) {
        certService.deleteCert(id);
        resetPlatformStateMachines();
        return WVPResult.success();
    }

    @Operation(summary = "删除证书并解除级联平台的绑定（用于级联编辑页删自己的证书）",
            description = "用于「国标级联 → 编辑」页删除本上级绑定的证书：证书此刻仍被本 platform 行按 ID 引用，"
                    + "直接走「删除证书」会被引用守卫拒绝。本接口先把 <code>wvp_platform.device_cert_id</code> / "
                    + "<code>platform_cert_id</code> 中等于该 ID 的置空，再执行删除。<br>"
                    + "<b>只解绑级联平台，不动设备的绑定</b> —— 设备侧那张证书与级联无关，"
                    + "擅自解绑会把一台正常在用的设备弄成「未配置证书」。设备仍引用时，删除照旧被拒绝并点名。<br>"
                    + "删除后丢弃证书状态机缓存。",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
    @Parameter(name = "id", description = "证书的主键 ID", required = true)
    @PostMapping("/unbind-and-delete/{id}")
    public WVPResult<?> unbindAndDelete(@PathVariable int id) {
        certService.unbindAndDeleteCert(id);
        resetPlatformStateMachines();
        return WVPResult.success();
    }

    @Operation(summary = "把证书绑定到级联平台（certId 省略或为空表示解绑）",
            description = "国密接入下「本平台设备证书」与「上级平台证书」都是<b>按上级各一张</b>的，"
                    + "因此这个归属必须显式记在 <code>wvp_platform</code> 上。没有它时，运行期只能靠国标 ID "
                    + "反查兜底 —— 兜底在「只有一张候选」时能用，接入第二个上级就会退化成"
                    + "「拒绝猜测、返回 null」，页面上也无从回显绑的是哪张。<br>"
                    + "<b>只写绑定那一列，不整行更新 platform</b> —— 绑定是证书槽自己的动作，"
                    + "不该受整行保存的前置校验与唯一键牵连（整行保存失败时绑定也跟着丢，页面上却看不出来）。<br>"
                    + "成功后丢弃证书状态机缓存。",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
    @Parameter(name = "platformId", description = "级联平台的主键 ID", required = true)
    @Parameter(name = "type", description = "证书类型，<b>只接受 DEVICE_IDENTITY（本平台设备证书）"
            + "与 TRUSTED_PLATFORM（上级平台证书）</b>", required = true)
    @Parameter(name = "certId", description = "证书主键 ID。<b>省略或传空表示解绑</b>")
    @PostMapping("/bind-platform")
    public WVPResult<?> bindPlatform(@RequestParam int platformId,
                                     @RequestParam String type,
                                     @RequestParam(required = false) Integer certId) {
        certService.bindToPlatform(platformId, type, certId);
        resetPlatformStateMachines();
        return WVPResult.success();
    }

    private void writeText(HttpServletResponse resp, String content, String filename) {
        if (content == null || content.isEmpty()) {
            resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
            return;
        }
        resp.setContentType(MediaType.APPLICATION_OCTET_STREAM_VALUE);
        resp.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");
        try {
            resp.getOutputStream().write(content.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            log.error("[GB35114] 下载文件失败", e);
        }
    }
}
