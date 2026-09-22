package com.genersoft.iot.vmp.gb35114.cert.controller;

import com.genersoft.iot.vmp.conf.security.JwtUtils;
import com.genersoft.iot.vmp.gb35114.cert.bean.Gb35114Ca;
import com.genersoft.iot.vmp.gb35114.cert.bean.Gb35114Cert;
import com.genersoft.iot.vmp.gb35114.cert.service.IGb35114CertService;
import com.genersoft.iot.vmp.gb35114.conf.Gb35114Config;
import com.genersoft.iot.vmp.gb35114.sip.Gb35114SecurityService;
import com.genersoft.iot.vmp.vmanager.bean.WVPResult;
import io.swagger.v3.oas.annotations.Operation;
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
 * <p>证书按用途分区管理：
 * <ul>
 *   <li><b>本地 CA</b>：本平台根 CA，私钥在本平台，用于签发；</li>
 *   <li><b>本地服务端证书</b>：本平台作 UAS，签 sign2；</li>
 *   <li><b>本地客户端证书</b>：本平台作 UAC，签 sign1；</li>
 *   <li><b>下级客户端证书</b>：签发给下级，私钥交付下级；</li>
 *   <li><b>上级服务端证书</b>：仅公钥，验 sign2。</li>
 * </ul>
 *
 * <p><b>私钥一律不通过接口下发</b>：本地身份证书的私钥与 CSR 存于同一条记录，
 * 仅在服务端签名时内部解密使用；删除记录即一并删除私钥。
 */
@Tag(name = "GB35114 证书管理")
@Slf4j
@RestController
@RequestMapping("/api/gb35114/cert")
public class Gb35114CertController {

    @Autowired
    private IGb35114CertService certService;

    /**
     * UAS 状态机持有签名身份与已协商的 VKEK。证书新增/吊销/删除/切换默认后必须丢弃
     * 缓存的状态机，否则会继续用旧私钥签 sign2 —— 设备验签失败即拒绝对后续信令服务。
     */
    @Autowired
    private Gb35114SecurityService gb35114SecurityService;

    @Autowired
    private Gb35114Config config;

    /** 丢弃全部 UAS 状态机缓存，下次注册时按最新证书集重建。 */
    private void resetPlatformStateMachines() {
        gb35114SecurityService.invalidateAllPlatformStateMachines();
    }

    /**
     * 证书相关策略（只读），供前端渲染策略感知的提示文案。
     *
     * <p>不返回任何私钥、加密口令或证书内容 —— 只有布尔与数值。
     */
    @Operation(summary = "查询证书策略（只读）", security = @SecurityRequirement(name = JwtUtils.HEADER))
    @GetMapping("/policy")
    public WVPResult<Map<String, Object>> policy() {
        Map<String, Object> policy = new LinkedHashMap<>();
        // 过期证书是否拒绝注册：默认 false，页面据此决定提示是「已过期」还是「将被拒绝注册」
        policy.put("rejectExpiredCert", config.isRejectExpiredCert());
        policy.put("certValidityDays", config.getCertValidityDays());
        return WVPResult.success(policy);
    }

    // ------------------------------------------------------------------
    // CA 管理
    // ------------------------------------------------------------------

    @Operation(summary = "生成本地根 CA", security = @SecurityRequirement(name = JwtUtils.HEADER))
    @PostMapping("/ca/generate")
    public WVPResult<Gb35114Ca> generateCa(@RequestParam String subjectCn,
                                           @RequestParam(required = false) String remark) {
        return WVPResult.success(certService.generateCa(subjectCn, remark));
    }

    @Operation(summary = "导入外部 CA（本地CA需私钥，上级CA仅证书）", security = @SecurityRequirement(name = JwtUtils.HEADER))
    @PostMapping("/ca/import")
    public WVPResult<Gb35114Ca> importCa(@RequestParam(required = false) String purpose,
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
        return WVPResult.success(certService.importCa(purpose, certPem, keyPem, remark));
    }

    @Operation(summary = "查询全部 CA", security = @SecurityRequirement(name = JwtUtils.HEADER))
    @GetMapping("/ca/list")
    public WVPResult<List<Gb35114Ca>> listCa(@RequestParam(required = false) String purpose) {
        return WVPResult.success(purpose == null || purpose.isEmpty()
                ? certService.queryAllCa() : certService.queryCaByPurpose(purpose));
    }

    @Operation(summary = "下载 CA 证书 PEM（交付对端导入，用于验签本平台证书）",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
    @GetMapping("/ca/download/{id}")
    public void downloadCa(HttpServletResponse resp, @PathVariable int id) {
        Gb35114Ca ca = certService.queryCa(id);
        writeText(resp, ca == null ? null : ca.getCertPem(),
                (ca == null || ca.getSubjectCn() == null ? "ca" : ca.getSubjectCn()) + ".crt");
    }

    @Operation(summary = "删除 CA（被证书引用时拒绝）", security = @SecurityRequirement(name = JwtUtils.HEADER))
    @DeleteMapping("/ca/delete/{id}")
    public WVPResult<?> deleteCa(@PathVariable int id) {
        certService.deleteCa(id);
        return WVPResult.success();
    }

    // ------------------------------------------------------------------
    // 本地身份证书（本平台持有私钥）
    // ------------------------------------------------------------------

    @Operation(summary = "创建证书请求（CSR）：生成密钥对并加密留存私钥",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
    @PostMapping("/csr/generate")
    public WVPResult<Gb35114Cert> generateCsr(Gb35114Cert profile,
                                              @RequestParam(defaultValue = "3650") int validityDays) {
        return WVPResult.success(certService.createPendingCsr(profile, validityDays));
    }

    @Operation(summary = "用本平台 CA 签发待签发记录", security = @SecurityRequirement(name = JwtUtils.HEADER))
    @PostMapping("/csr/sign/{id}")
    public WVPResult<Gb35114Cert> signPending(@PathVariable int id,
                                              @RequestParam int caId,
                                              @RequestParam(defaultValue = "3650") int validityDays) {
        return WVPResult.success(certService.signPendingByCa(id, caId, validityDays));
    }

    @Operation(summary = "用外部 CA 返回的证书回填待签发记录（校验公私钥配对）",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
    @PostMapping("/csr/complete/{id}")
    public WVPResult<Gb35114Cert> completePending(@PathVariable int id,
                                                  @RequestParam("certFile") MultipartFile certFile) {
        try {
            String certPem = new String(certFile.getBytes(), StandardCharsets.UTF_8);
            return WVPResult.success(certService.completePendingWithCert(id, certPem));
        } catch (Exception e) {
            throw new RuntimeException("读取证书文件失败: " + e.getMessage(), e);
        }
    }

    @Operation(summary = "导出待签发记录的 CSR（交付外部 CA）", security = @SecurityRequirement(name = JwtUtils.HEADER))
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

    @Operation(summary = "生成本平台自签身份证书", security = @SecurityRequirement(name = JwtUtils.HEADER))
    @PostMapping("/selfsigned")
    public WVPResult<Gb35114Cert> selfSigned(Gb35114Cert profile,
                                             @RequestParam(defaultValue = "3650") int validityDays) {
        return WVPResult.success(certService.generateSelfSigned(profile, validityDays));
    }

    @Operation(summary = "导入本平台身份证书（证书 + 私钥，校验配对）",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
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
            security = @SecurityRequirement(name = JwtUtils.HEADER))
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
            security = @SecurityRequirement(name = JwtUtils.HEADER))
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

    @Operation(summary = "导入对端证书（仅公钥：上级服务端证书 / 下级客户端证书）",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
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

    @Operation(summary = "查询证书列表（不含私钥）", security = @SecurityRequirement(name = JwtUtils.HEADER))
    @GetMapping("/list")
    public WVPResult<List<Gb35114Cert>> list(@RequestParam(required = false) String purpose) {
        return WVPResult.success(purpose == null || purpose.isEmpty()
                ? certService.queryAllCerts() : certService.queryCertsByPurpose(purpose));
    }

    @Operation(summary = "按国标 ID 查询证书", security = @SecurityRequirement(name = JwtUtils.HEADER))
    @GetMapping("/list/{gbId}")
    public WVPResult<List<Gb35114Cert>> listByGbId(@PathVariable String gbId) {
        return WVPResult.success(certService.queryByGbId(gbId));
    }

    @Operation(summary = "下载证书 PEM", security = @SecurityRequirement(name = JwtUtils.HEADER))
    @GetMapping("/download/cert/{id}")
    public void downloadCert(HttpServletResponse resp, @PathVariable int id) {
        Gb35114Cert cert = certService.queryCert(id);
        writeText(resp, cert == null ? null : cert.getCertPem(),
                (cert == null || cert.getGbId() == null ? "cert" : cert.getGbId()) + ".crt");
    }

    @Operation(summary = "吊销证书", security = @SecurityRequirement(name = JwtUtils.HEADER))
    @PostMapping("/revoke/{id}")
    public WVPResult<?> revoke(@PathVariable int id) {
        certService.revokeCert(id);
        resetPlatformStateMachines();
        return WVPResult.success();
    }

    @Operation(summary = "设为默认服务器证书（未绑定设备的设备注册时使用该证书签 sign2）",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
    @PostMapping("/default/{id}")
    public WVPResult<?> setDefault(@PathVariable int id) {
        certService.setDefaultServerIdentity(id);
        resetPlatformStateMachines();
        return WVPResult.success();
    }

    @Operation(summary = "复用现有密钥对再签一张服务端证书（公钥不变，设备无需重新配置）",
            security = @SecurityRequirement(name = JwtUtils.HEADER))
    @PostMapping("/reissue/{sourceId}")
    public WVPResult<Gb35114Cert> reissue(@PathVariable int sourceId,
                                          @RequestBody Gb35114Cert profile,
                                          @RequestParam(required = false) Integer caId,
                                          @RequestParam(defaultValue = "3650") int validityDays) {
        Gb35114Cert cert = certService.reissueServerIdentity(sourceId, profile, caId, validityDays);
        // 新证书与源证书公钥相同，签名身份未变，但仍清一次缓存以保证状态机持有最新记录
        resetPlatformStateMachines();
        return WVPResult.success(cert);
    }

    @Operation(summary = "删除证书（本地身份证书连同私钥一并删除）", security = @SecurityRequirement(name = JwtUtils.HEADER))
    @DeleteMapping("/delete/{id}")
    public WVPResult<?> delete(@PathVariable int id) {
        certService.deleteCert(id);
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
