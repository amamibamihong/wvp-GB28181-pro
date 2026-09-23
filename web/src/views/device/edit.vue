<template>
  <div id="deviceEdit" v-loading="isLoging">
    <el-dialog
      v-el-drag-dialog
      title="设备编辑"
      width="40%"
      top="2rem"
      :close-on-click-modal="false"
      :visible.sync="showDialog"
      :destroy-on-close="true"
      @close="close()"
    >
      <div id="shared" style="margin-right: 50px;">
        <el-form ref="form" :rules="rules" :model="form" label-width="100px">
          <el-form-item label="设备编号" prop="deviceId">
            <el-input v-if="isEdit" v-model="form.deviceId" disabled />
            <el-input v-if="!isEdit" v-model="form.deviceId" clearable />
          </el-form-item>

          <el-form-item label="设备名称" prop="name">
            <el-input v-model="form.name" clearable />
          </el-form-item>
          <el-form-item label="密码" prop="password">
            <el-input v-model="form.password" clearable />
          </el-form-item>
          <el-form-item label="注册方式" prop="registerWay">
            <el-select v-model="form.registerWay" style="float: left; width: 100%" placeholder="请选择注册方式">
              <el-option label="摘要认证（默认）" :value="1" />
              <el-option label="证书双向认证（GB35114）" :value="3" />
              <el-option label="证书单向认证（GB35114）" :value="4" />
            </el-select>
            <div class="hint" style="font-size:12px;color:#909399;line-height:1.6;margin-top:4px;">
              摄像头用证书方式接入时需选 3/4，并先在证书管理-下级客户端证书中导入该设备的证书。
            </div>
          </el-form-item>
          <el-form-item v-if="isGb35114CertWay" label="服务端证书" prop="serverCertId">
            <el-select v-model="form.serverCertId" clearable style="float: left; width: 100%"
                       placeholder="不绑定，使用平台的服务端证书">
              <el-option
                v-for="item in serverCertList"
                :key="item.id"
                :label="`#${item.id} ${item.subjectCn || item.gbId || ''}`"
                :value="item.id"
              />
            </el-select>
            <div class="hint" style="font-size:12px;color:#909399;line-height:1.6;margin-top:4px;">
              平台签 sign2 用的私钥必须与摄像头里导入的平台证书公钥配对，否则摄像头验签失败、
              注册后拒绝对信令服务（表现为目录查询 403、通道同步不上）。<br />
              摄像头只信任某一张特定证书时，在此绑定它；留空则使用「证书管理-本地服务端证书」
              中的那张（该用途后端只允许存在一张，不存在选择歧义）。
            </div>
          </el-form-item>
          <el-form-item label="收流IP" prop="sdpIp">
            <el-input v-model="form.sdpIp" type="sdpIp" clearable />
          </el-form-item>
          <el-form-item label="流媒体ID" prop="mediaServerId">
            <el-select v-model="form.mediaServerId" style="float: left; width: 100%">
              <el-option key="auto" label="自动负载最小" value="auto" />
              <el-option
                v-for="item in mediaServerList"
                :key="item.id"
                :label="item.id"
                :value="item.id"
              />
            </el-select>
          </el-form-item>

          <el-form-item label="字符集" prop="charset">
            <el-select v-model="form.charset" style="float: left; width: 100%">
              <el-option key="GB2312" label="GB2312" value="gb2312" />
              <el-option key="UTF-8" label="UTF-8" value="utf-8" />
            </el-select>
          </el-form-item>
          <el-form-item label="坐标系" prop="geoCoordSys">
            <el-select v-model="form.geoCoordSys" style="float: left; width: 100%">
              <el-option key="WGS84" label="WGS84" value="gb2312" />
              <el-option key="GCJ02" label="GCJ02" value="utf-8" />
            </el-select>
          </el-form-item>
          <el-form-item label="其他选项">
            <el-checkbox v-model="form.ssrcCheck" label="SSRC校验" style="float: left" />
            <el-checkbox v-model="form.asMessageChannel" label="作为消息通道" style="float: left" />
            <el-checkbox v-model="form.broadcastPushAfterAck" label="收到ACK后发流" style="float: left" />
          </el-form-item>
          <el-form-item>
            <div style="float: right;">
              <el-button type="primary" @click="onSubmit">确认</el-button>
              <el-button @click="close">取消</el-button>
            </div>

          </el-form-item>
        </el-form>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import elDragDialog from '@/directive/el-drag-dialog'
import { listCert, PURPOSE_SERVER_IDENTITY } from '@/api/gb35114'

export default {
  name: 'DeviceEdit',
  directives: { elDragDialog },
  props: {},
  data() {
    return {
      listChangeCallback: null,
      showDialog: false,
      isLoging: false,
      hostNames: [],
      mediaServerList: [], // 滅体节点列表
      serverCertList: [], // 本地服务端证书（供绑定）
      form: {},
      isEdit: false,
      rules: {
        deviceId: [{ required: true, message: '请输入设备编号', trigger: 'blur' }]
      }
    }
  },
  computed: {
    /** 仅证书注册方式（3/4）才需要选择服务端证书。 */
    isGb35114CertWay() {
      return this.form.registerWay === 3 || this.form.registerWay === 4
    }
  },
  created() {},
  methods: {
    openDialog: function(row, callback) {
      console.log(row)
      this.showDialog = true
      this.isEdit = false
      if (row) {
        this.isEdit = true
      }
      this.form = {}
      this.listChangeCallback = callback
      if (row != null) {
        this.form = row
      }
      this.getMediaServerList()
      this.getServerCertList()
    },
    /**
     * 可绑定的服务端证书：仅「本地服务端证书」，且必须已签发、持有私钥、未吊销。
     *
     * <p>不过滤已过期的：签名身份是<b>密钥对</b>而非证书，同一密钥对下多张有效期不同的
     * 证书对设备完全等价（设备只存公钥）。绑定其中已过期的一张后，平台会自动改用同组
     * 还有效的兄弟证书，设备无感。因此过期与否不构成「能不能绑」的理由。
     */
    getServerCertList: function() {
      listCert(PURPOSE_SERVER_IDENTITY).then(data => {
        this.serverCertList = (data || []).filter(
          item => item.certPem && item.hasKey && !item.revoked
        )
      }).catch(() => { this.serverCertList = [] })
    },
    getMediaServerList: function() {
      this.$store.dispatch('server/getOnlineMediaServerList')
        .then((data) => {
          this.mediaServerList = data
        })
    },
    onSubmit: function() {
      if (this.isEdit) {
        this.$store.dispatch('device/update', this.form)
          .then((data) => {
            this.listChangeCallback()
          })
      } else {
        this.$store.dispatch('device/add', this.form)
          .then((data) => {
            this.listChangeCallback()
          })
      }
    },
    close: function() {
      this.showDialog = false
      this.$refs.form.resetFields()
    }
  }
}
</script>
