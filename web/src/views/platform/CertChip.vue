<template>
  <!--
    证书摘要「芯片」：一行放下「哪张 + 状态」，完整信息（全 CN、国标 ID、签发来源、
    有效期）放进悬浮提示。

    编辑页表单列宽有限，而证书 CN 可长达 44 字符（国标 ID_22 位密码模块 ID），
    直接铺开会把表单撑得很难看，所以这里截断 + 省略号，需要时悬浮看全。
  -->
  <div class="cert-chip" :title="tooltip">
    <span class="cert-chip-id">#{{ cert.id }}</span>
    <span class="cert-chip-cn">{{ cert.subjectCn || '未命名' }}</span>
    <el-tag size="mini" effect="plain" :type="status.type">{{ status.text }}</el-tag>
  </div>
</template>

<script>
export default {
  name: 'CertChip',
  props: {
    cert: { type: Object, required: true }
  },
  computed: {
    /**
     * 状态：待签发 / 已过期 / 有效。
     *
     * 过期与否只如实标出，不做取舍 —— 是否拦截注册由后端策略（rejectExpiredCert）决定，
     * 页面不替它下结论。
     */
    status() {
      if (!this.cert.certPem) return { text: '待签发', type: 'warning' }
      if (this.expired) return { text: '已过期', type: 'danger' }
      return { text: '有效', type: 'success' }
    },
    /** 证书是否已过有效期（后端存 'yyyy-MM-dd HH:mm:ss'，Safari 需把空格换成 T） */
    expired() {
      if (!this.cert.notAfter) return false
      const t = Date.parse(String(this.cert.notAfter).replace(' ', 'T'))
      return !isNaN(t) && t < Date.now()
    },
    /** 悬浮提示：把芯片上放不下的信息补全 */
    tooltip() {
      const lines = [
        'CN：' + (this.cert.subjectCn || '未命名'),
        '国标 ID：' + (this.cert.gbId || '（无）'),
        '签发：' + (this.cert.caId ? 'CA 签发' : '自签')
      ]
      if (!this.cert.certPem) {
        lines.push('状态：待签发（只有 CSR 与私钥，尚无证书）')
      } else if (this.cert.notAfter) {
        lines.push('有效期至：' + this.cert.notAfter)
      }
      return lines.join('\n')
    }
  }
}
</script>

<style scoped>
.cert-chip {
  display: flex;
  align-items: center;
  gap: 6px;
  min-width: 0;
  line-height: 1.6;
}
.cert-chip-id {
  flex: none;
  font-family: Menlo, Consolas, monospace;
  font-size: 12px;
  color: #909399;
}
.cert-chip-cn {
  flex: 1 1 auto;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 13px;
  color: #303133;
}
.cert-chip .el-tag {
  flex: none;
}
</style>
