<template>
  <div id="PlatformEdit" style="width: 100%">
    <div id="shared" style="text-align: right; margin-top: 1rem; background-color: #FFFFFF; padding-top: 2rem;">
      <el-row :gutter="24">
        <el-col :span="11">
          <el-form ref="platform1" :rules="rules" :model="value" size="medium" label-width="160px">
            <el-form-item label="名称" prop="name">
              <el-input v-model="value.name" />
            </el-form-item>
            <el-form-item label="SIP服务国标编码" prop="serverGBId">
              <el-input v-model="value.serverGBId" clearable @input="serverGBIdChange" />
            </el-form-item>
            <el-form-item label="SIP服务国标域" prop="serverGBDomain">
              <el-input v-model="value.serverGBDomain" clearable />
            </el-form-item>
            <el-form-item label="SIP服务IP" prop="serverIp">
              <el-input v-model="value.serverIp" clearable />
            </el-form-item>
            <el-form-item label="SIP服务端口" prop="serverPort">
              <el-input v-model="value.serverPort" clearable type="number" />
            </el-form-item>
            <el-form-item label="设备国标编号" prop="deviceGBId">
              <el-input v-model="value.deviceGBId" clearable @input="deviceGBIdChange" />
            </el-form-item>
            <el-form-item label="本地IP" prop="deviceIp">
              <el-select v-model="value.deviceIp" placeholder="请选择与上级相通的网卡" style="width: 100%">
                <el-option
                  v-for="ip in deviceIps"
                  :key="ip"
                  :label="ip"
                  :value="ip"
                />
              </el-select>
            </el-form-item>
            <el-form-item label="本地端口" prop="devicePort">
              <el-input v-model="value.devicePort" :disabled="true" type="number" />
            </el-form-item>

            <el-form-item label="SIP认证用户名" prop="username">
              <el-input v-model="value.username" />
            </el-form-item>
            <el-form-item label="SIP认证密码" prop="password">
              <el-input v-model="value.password" />
            </el-form-item>
            <el-form-item label="注册周期(秒)" prop="expires">
              <el-input v-model="value.expires" />
              <!--
                GB 35114—2017 6.14.3：VKEK 更新周期不大于 1 天。本实现里 VKEK 只在注册
                握手时生成，故注册周期即 VKEK 更新周期。43026 §7.13 表 13 序号 1 是必测项，
                且测的是配置值本身。这里只提示、不阻断（后端 PlatformController 会钳制，
                存量超限配置压到合规值即可继续工作），避免把已能跑的接入挡在门外。
              -->
              <div v-if="isGb35114Way" class="gb35114-vkek-tip">
                国密接入下注册周期即 VKEK 更新周期，GB 35114—2017 6.14.3 要求不大于 1 天（86400 秒），
                超出将被自动改为 86400。
              </div>
            </el-form-item>
            <el-form-item label="心跳周期(秒)" prop="keepTimeout">
              <el-input v-model="value.keepTimeout" />
            </el-form-item>
          </el-form>
        </el-col>
        <el-col :span="12">
          <el-form ref="platform2" :rules="rules" :model="value" size="medium" label-width="160px">
            <el-form-item label="SDP发流IP" prop="sendStreamIp">
              <el-input v-model="value.sendStreamIp" />
            </el-form-item>
            <el-form-item label="信令传输" prop="transport">
              <el-select
                v-model="value.transport"
                style="width: 100%"
                placeholder="请选择信令传输方式"
              >
                <el-option label="UDP" value="UDP" />
                <el-option label="TCP" value="TCP" />
              </el-select>
            </el-form-item>
            <el-form-item label="保密属性">
              <el-select v-model="value.secrecy" style="width: 100%" placeholder="请选择保密属性">
                <el-option label="不涉密" :value="0" />
                <el-option label="涉密" :value="1" />
              </el-select>
            </el-form-item>
            <el-form-item label="注册方式" prop="registerWay">
              <el-select
                v-model="value.registerWay"
                style="width: 100%"
                placeholder="请选择注册方式"
              >
                <el-option label="摘要认证（RFC3261）" :value="1" />
                <el-option label="口令双向认证" :value="2" />
                <el-option label="证书双向认证（GB35114）" :value="3" />
                <el-option label="证书单向认证（GB35114）" :value="4" />
              </el-select>
            </el-form-item>

            <!-- 新增态：证书槽不渲染，给一句指路。选了 3/4 才提示，不阻断提交。 -->
            <el-alert
              v-if="!isEdit && isGb35114Way"
              class="gb35114-create-tip"
              type="info"
              :closable="false"
              show-icon
              title="该上级已启用国密接入。客户端证书、上级平台证书与 CA 需要在保存后到编辑页创建/上传，在此之前本上级无法完成国密注册。"
            />

            <!--
              编辑态才渲染证书槽：这些动作都要把「本上级的 id」写进 platform 行的引用列，
              而新增时 platform 还没有 id，只能先落一张游离证书。
              每个动作即时落库（各自独立接口），不依赖点「保存」；onSubmit 仍提交整个 value。
            -->
            <template v-if="isEdit && isGb35114Way">
              <el-form-item label="国密设备证书">
                <div class="cert-slot">
                  <!--
                    渲染依据是 effectiveDeviceCert（显式绑定优先，否则运行期兜底解析）而不是
                    单看绑定列：库里 device_cert_id 为 NULL、但按国标 ID 能解析到证书时，
                    注册其实跑得通。这时若显示「创建 CSR」，会让人再建一张 —— 而真正的
                    问题是归属没记下来，不是缺证书。
                  -->
                  <template v-if="!effectiveDeviceCert">
                    <el-button size="mini" type="primary" @click="openDeviceCsr">创建 CSR</el-button>
                    <span class="cert-slot-hint">本平台作下级签 sign1，必须由上级签发</span>
                  </template>
                  <!-- 待签发态：有 CSR 无证书 -->
                  <template v-else-if="!effectiveDeviceCert.certPem">
                    <cert-chip :cert="effectiveDeviceCert" />
                    <div class="cert-actions">
                      <el-button size="mini" @click="downloadCsrFile(effectiveDeviceCert)">导出 CSR</el-button>
                      <el-button size="mini" type="warning" @click="openCompletePending(effectiveDeviceCert)">回填</el-button>
                      <el-button size="mini" type="danger" plain @click="unbindAndDelete(effectiveDeviceCert, 'deviceCertId')">删除</el-button>
                    </div>
                  </template>
                  <!-- 已签发态 -->
                  <template v-else>
                    <cert-chip :cert="effectiveDeviceCert" />
                    <div class="cert-actions">
                      <el-button size="mini" @click="downloadCertFile(effectiveDeviceCert)">导出证书</el-button>
                      <el-button size="mini" type="danger" plain @click="unbindAndDelete(effectiveDeviceCert, 'deviceCertId')">删除</el-button>
                    </div>
                  </template>
                </div>
                <!-- 有候选但不止一张，后端会拒绝猜测：说明清楚，否则注册失败时无从查起。
                     「没绑定但能唯一定位」的情形不用提示 —— autoBindFallbacks 已静默绑定。 -->
                <div v-if="!deviceCert && !effectiveDeviceCert && deviceCertAmbiguous" class="cert-fallback">
                  <i class="el-icon-warning-outline" />
                  <span>同类型证书不止一张，按国标 ID <b>{{ platformGbId }}</b> 无法定位
                    —— 注册会因取不到证书而失败，请在此绑定</span>
                </div>
              </el-form-item>

              <el-form-item label="上级平台证书">
                <div class="cert-slot">
                  <template v-if="!effectivePlatformCert">
                    <el-button size="mini" type="primary" @click="openPeerImport">导入上级证书</el-button>
                    <span class="cert-slot-hint">仅公钥，用于验上级下发的 sign2</span>
                  </template>
                  <template v-else>
                    <cert-chip :cert="effectivePlatformCert" />
                    <div class="cert-actions">
                      <el-button size="mini" @click="downloadCertFile(effectivePlatformCert)">导出证书</el-button>
                      <el-button size="mini" type="danger" plain @click="unbindAndDelete(effectivePlatformCert, 'platformCertId')">删除</el-button>
                    </div>
                  </template>
                </div>
                <div v-if="!platformCert && !effectivePlatformCert && platformCertAmbiguous" class="cert-fallback">
                  <i class="el-icon-warning-outline" />
                  <span>同类型证书不止一张，按国标 ID <b>{{ value.serverGBId }}</b> 无法定位
                    —— 上级下发的 sign2 将无法验签，请在此绑定</span>
                </div>
                <!--
                  签发者未导入：导入那一刻后端也提示过一次，但那是一次性通知，划过去就没了。
                  这个问题的发作点在「级联注册被拒」—— 是几天后的事，届时翻日志才知道原因。
                  故在此常驻，判据与列表页「签发方式」列完全一致（caId 为空且非自签）。

                  文案分两态：链校验开着（默认）时确实会被拒；关掉了就只是"将来打开会出问题"，
                  此时说「会被拒」是过度告警 —— 现场会照着一条不存在的故障去排查。
                -->
                <div v-if="effectivePlatformCert && issuerUnknown(effectivePlatformCert)" class="cert-fallback">
                  <i class="el-icon-warning-outline" />
                  <span v-if="policy.verifyUpstreamCertChain">这张证书的签发者（<b>{{ effectivePlatformCert.issuerDn || '未知' }}</b>）未导入本平台，
                    证书链校验不通过 —— 上级下发的 sign2 将无法验签、级联注册会被拒。
                    请把签发它的 CA 导入下方「CA 证书」，或让上级改用你已导入的 CA 重新颁发</span>
                  <span v-else>这张证书的签发者（<b>{{ effectivePlatformCert.issuerDn || '未知' }}</b>）未导入本平台。
                    当前已关闭上级证书链校验（gb35114.verify-upstream-cert-chain=false），不影响注册；
                    但该项一旦改回 true 就会断链，建议把签发它的 CA 导入下方「CA 证书」</span>
                </div>
              </el-form-item>

              <el-form-item label="CA 证书">
                <div class="cert-slot">
                  <el-button size="mini" @click="openCaImport">导入 CA</el-button>
                  <span class="cert-slot-hint">导入签发上级证书的 CA；删除入口在「国密证书管理」页</span>
                </div>
              </el-form-item>
            </template>
            <el-form-item label="目录分组" prop="catalogGroup">
              <el-select
                v-model="value.catalogGroup"
                style="width: 100%"
                placeholder="请选择目录分组"
              >
                <el-option label="1" value="1" />
                <el-option label="2" value="2" />
                <el-option label="4" value="4" />
                <el-option label="8" value="8" />
              </el-select>
            </el-form-item>
            <el-form-item label="字符集" prop="characterSet">
              <el-select
                v-model="value.characterSet"
                style="width: 100%"
                placeholder="请选择字符集"
              >
                <el-option label="GB2312" value="GB2312" />
                <el-option label="UTF-8" value="UTF-8" />
              </el-select>
            </el-form-item>
            <el-form-item label="行政区划" prop="civilCode">
              <el-input v-model="value.civilCode" clearable />
            </el-form-item>
            <el-form-item label="平台厂商" prop="manufacturer">
              <el-input v-model="value.manufacturer" clearable />
            </el-form-item>
            <el-form-item label="平台型号" prop="model">
              <el-input v-model="value.model" clearable />
            </el-form-item>
            <el-form-item label="平台安装地址" prop="address">
              <el-input v-model="value.address" clearable />
            </el-form-item>
            <el-form-item label="其他选项">
              <div style="text-align: left">
                <el-checkbox v-model="value.enable" label="启用" @change="checkExpires" />
                <!--                <el-checkbox label="云台控制" v-model="value.ptz"></el-checkbox>-->
                <el-checkbox v-model="value.rtcp" label="RTCP保活" @change="rtcpCheckBoxChange" />
                <el-checkbox v-model="value.asMessageChannel" label="消息通道" />
                <el-checkbox v-model="value.autoPushChannel" label="主动推送通道" />
                <el-checkbox
                  v-model="value.catalogWithPlatform"
                  label="推送平台信息"
                  :true-label="1"
                  :false-label="0"
                />
                <el-checkbox
                  v-model="value.catalogWithGroup"
                  label="推送分组信息"
                  :true-label="1"
                  :false-label="0"
                />
                <el-checkbox
                  v-model="value.catalogWithRegion"
                  label="推送行政区划"
                  :true-label="1"
                  :false-label="0"
                />
              </div>
            </el-form-item>
            <el-form-item>
              <el-button type="primary" @click="onSubmit">{{ onSubmit_text }} </el-button>
              <el-button @click="close">取消</el-button>
            </el-form-item>
          </el-form>
        </el-col>
      </el-row>
    </div>

    <!-- ============ 回填上级签发的证书 ============ -->
    <el-dialog title="回填证书" :visible.sync="completeDialog.visible" width="480px" :close-on-click-modal="false">
      <el-form label-width="130px" size="small">
        <el-form-item label="待回填记录">
          <span>{{ completeDialog.subjectCn }}（#{{ completeDialog.id }}）</span>
        </el-form-item>
        <el-form-item label="证书文件">
          <input type="file" ref="completeCertFile" @change="onCompleteFileChange" />
        </el-form-item>
      </el-form>
      <div class="hint">把上级签发好的证书回填到这条待签发记录。服务端会校验证书公钥与本地留存私钥是否配对，
        不配对则拒绝 —— 配对是硬要求：不配对时上级验 sign1 必然失败，而本平台日志一切正常。</div>
      <div slot="footer">
        <el-button size="mini" @click="completeDialog.visible = false">取消</el-button>
        <el-button size="mini" type="primary" :loading="completeDialog.loading" @click="submitCompletePending">确定</el-button>
      </div>
    </el-dialog>

    <!-- ============ 导入上级平台证书（仅公钥） ============ -->
    <el-dialog title="导入上级平台证书" :visible.sync="peerImportDialog.visible" width="520px" :close-on-click-modal="false">
      <el-form label-width="130px" size="small">
        <el-form-item label="上级国标 ID">
          <el-input v-model="peerImportDialog.gbId" placeholder="上级平台国标编号" />
        </el-form-item>
        <el-form-item label="证书文件">
          <input type="file" ref="peerCertFile" @change="onPeerFileChange" />
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="peerImportDialog.remark" placeholder="可选" />
        </el-form-item>
      </el-form>
      <div class="hint">上级平台证书仅保存公钥；即使选择了私钥文件也不会被保存。<br>
        导入时会检查签发者是否已在「CA 证书管理」里 —— 没有只提示、不拦截：是否信任由注册时的
        证书链校验实时判定，CA 可以先于证书导入，也可以后补。</div>
      <div slot="footer">
        <el-button size="mini" @click="peerImportDialog.visible = false">取消</el-button>
        <el-button size="mini" type="primary" :loading="peerImportDialog.loading" @click="submitPeerImport">导入</el-button>
      </div>
    </el-dialog>

    <!-- ============ 导入 CA（受信任的 CA，仅公钥） ============ -->
    <el-dialog title="导入 CA 证书" :visible.sync="caImportDialog.visible" width="480px" :close-on-click-modal="false">
      <el-form label-width="130px" size="small">
        <el-form-item label="CA 证书文件">
          <input type="file" ref="caCertFile" @change="onCaFileChange" />
        </el-form-item>
      </el-form>
      <div class="hint">导入签发上级平台证书的 CA，用于验证上级证书链。重复导入会各留一份记录，
        删除入口在「国密证书管理」页的 CA 证书管理。</div>
      <div slot="footer">
        <el-button size="mini" @click="caImportDialog.visible = false">取消</el-button>
        <el-button size="mini" type="primary" :loading="caImportDialog.loading" @click="submitCaImport">导入</el-button>
      </div>
    </el-dialog>

    <!--
      创建国密设备证书的 CSR。字段与「国密证书管理」页的同名对话框一致 ——
      同一件事两个入口，不该长得不一样。
    -->
    <el-dialog title="创建证书请求（CSR）· 国密设备证书"
               :visible.sync="csrDialog.visible" width="620px" :close-on-click-modal="false">
      <el-form ref="csrForm" :model="csrDialog.form" :rules="csrRules" label-width="130px" size="small">
        <el-form-item label="主题（CN）" prop="subjectCn">
          <el-input v-model="csrDialog.form.subjectCn" placeholder="国标ID_密码模块ID"
                    @input="syncCsrGbIdFromCn" />
          <span class="hint-inline">默认「本平台在该上级处的国标 ID_密码模块 ID」（附录 A 表 A.1 第 6 项），
            已按 SIP 认证用户名填好；接入多个上级时若需另编编码防冲突，可直接改这里</span>
        </el-form-item>
        <el-row>
          <el-col :span="12">
            <el-form-item label="国家（C）">
              <el-input v-model="csrDialog.form.country" placeholder="CN" />
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item label="省份（ST）">
              <el-input v-model="csrDialog.form.province" />
            </el-form-item>
          </el-col>
        </el-row>
        <el-row>
          <el-col :span="12">
            <el-form-item label="城市（L）">
              <el-input v-model="csrDialog.form.locality" />
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item label="组织（O）">
              <el-input v-model="csrDialog.form.organization" />
            </el-form-item>
          </el-col>
        </el-row>
        <el-form-item label="组织单位（OU）">
          <el-input v-model="csrDialog.form.organizationalUnit" />
        </el-form-item>
        <el-form-item label="有效期（天）">
          <el-input-number v-model="csrDialog.form.validityDays" :min="1" :max="36500" controls-position="right" />
          <span class="hint-inline">自签发时刻起算</span>
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="csrDialog.form.remark" placeholder="可选" />
        </el-form-item>
      </el-form>
      <div slot="footer">
        <el-button size="mini" @click="csrDialog.visible = false">取消</el-button>
        <el-button size="mini" type="primary" :loading="csrDialog.loading" @click="submitDeviceCsr">生成 CSR</el-button>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import {
  listCert, getCertPolicy, createCsr, completePendingCsr, downloadCsr, downloadCert,
  importPeer, importCa, unbindAndDeleteCert, bindCertToPlatform,
  TYPE_DEVICE_IDENTITY, TYPE_TRUSTED_PLATFORM, TYPE_TRUSTED_CA
} from '@/api/gb35114'
import certChip from './CertChip.vue'

export default {
  name: 'PlatformEdit',
  components: { certChip },
  props: ['value', 'closeEdit', 'deviceIps'],
  data() {
    var deviceGBIdRules = async(rule, value, callback) => {
      console.log(value)
      if (value === '') {
        callback(new Error('请输入设备国标编号'))
      } else {
        var exit = await this.deviceGBIdExit(value)
        if (exit) {
          callback(new Error('设备国标编号格式错误或已存在'))
        } else {
          callback()
        }
      }
    }
    return {
      listChangeCallback: null,
      showDialog: false,
      isLoging: false,
      onSubmit_text: '保存',
      certList: [],

      // 证书槽的对话框与文件暂存。每个动作即时落库，不依赖点「保存」。
      completeDialog: { visible: false, loading: false, id: null, subjectCn: '' },
      completeCertFile: null,
      peerImportDialog: { visible: false, loading: false, gbId: '', remark: '' },
      peerCertFile: null,
      caImportDialog: { visible: false, loading: false },
      caCertFile: null,

      /**
       * 创建 CSR 的对话框。表单字段与「国密证书管理」页的同名对话框一致 ——
       * 同一件事两个入口，长得不一样只会让人以为做的事不一样。
       */
      csrDialog: {
        visible: false, loading: false,
        form: { subjectCn: '', gbId: '', country: 'CN', province: '', locality: '',
          organization: '', organizationalUnit: '', remark: '', validityDays: 3650 }
      },
      csrRules: {
        subjectCn: [{ required: true, message: '请输入主题 CN', trigger: 'blur' }]
      },
      /**
       * 证书策略（只读）。本页用到两项：
       * <ul>
       *   <li>moduleId —— 主题里密码模块 ID 段的默认值，取自后端配置 `gb35114.module-id`，
       *       留空即 22 个 0；</li>
       *   <li>verifyUpstreamCertChain —— 上级证书链校验是否开启（默认 true）。决定
       *       「签发者未导入」那条告警说的是「会被拒」还是「将来打开会出问题」。</li>
       * </ul>
       */
      policy: { moduleId: '', verifyUpstreamCertChain: true },

      rules: {
        name: [{ required: true, message: '请输入平台名称', trigger: 'blur' }],
        serverGBId: [
          { required: true, message: '请输入SIP服务国标编码', trigger: 'blur' }
        ],
        serverGBDomain: [
          { required: true, message: '请输入SIP服务国标域', trigger: 'blur' }
        ],
        serverIp: [{ required: true, message: '请输入SIP服务IP', trigger: 'blur' }],
        serverPort: [{ required: true, message: '请输入SIP服务端口', trigger: 'blur' }],
        deviceGBId: [{ validator: deviceGBIdRules, trigger: 'blur' }],
        username: [{ required: false, message: '请输入SIP认证用户名', trigger: 'blur' }],
        password: [{ required: false, message: '请输入SIP认证密码', trigger: 'blur' }],
        expires: [{ required: true, message: '请输入注册周期', trigger: 'blur' }],
        keepTimeout: [{ required: true, message: '请输入心跳周期', trigger: 'blur' }],
        transport: [{ required: true, message: '请选择信令传输', trigger: 'blur' }],
        characterSet: [{ required: true, message: '请选择编码字符集', trigger: 'blur' }],
        deviceIp: [{ required: true, message: '请选择本地IP', trigger: 'blur' }]
      },

      saveLoading: false
    }
  },
  watch: {
    value(newValue, oldValue) {
      this.streamProxy = newValue
    }
  },
  computed: {
    /** 编辑态：platform 已有 id。新增时证书槽整体不渲染（见模板里的说明）。 */
    isEdit() {
      return !!(this.value && this.value.id)
    },
    /** 当前选的是不是 GB35114 注册方式（3-证书双向 / 4-证书单向）。 */
    isGb35114Way() {
      return this.value && (this.value.registerWay === 3 || this.value.registerWay === 4)
    },
    deviceCerts() {
      // 本平台作下级接入上级时用「客户端证书（本平台）」（UAC，签 sign1）
      return (this.certList || []).filter(c => c.type === TYPE_DEVICE_IDENTITY && !c.revoked)
    },
    platformCerts() {
      // 验上级下发的 sign2，用「服务端证书（上级平台）」（仅公钥）
      return (this.certList || []).filter(c => c.type === TYPE_TRUSTED_PLATFORM && !c.revoked)
    },
    /** 当前绑定的国密设备证书（按 value.deviceCertId 从列表取；未绑定为 null）。 */
    deviceCert() {
      return this.findCert(this.value && this.value.deviceCertId)
    },
    /** 当前绑定的上级平台证书。 */
    platformCert() {
      return this.findCert(this.value && this.value.platformCertId)
    },
    /**
     * 运行期<b>实际会用到</b>的那张「本平台设备证书」：显式绑定优先，否则按国标 ID 兜底解析。
     *
     * <p>口径必须与后端 {@code Gb35114SecurityService.uacStateMachine} 完全一致 ——
     * 页面显示的和真正拿去签 sign1 的若不是同一张，比不显示更糟。
     */
    effectiveDeviceCert() {
      return this.deviceCert || this.resolveFallback(TYPE_DEVICE_IDENTITY, this.platformGbId)
    },
    /** 运行期实际会用到的那张「上级平台证书」。口径同上，按上级国标编码匹配。 */
    effectivePlatformCert() {
      return this.platformCert || this.resolveFallback(TYPE_TRUSTED_PLATFORM, this.value && this.value.serverGBId)
    },
    /** 设备证书有候选、但既没绑定也无法唯一定位 —— 后端此时拒绝猜测，注册会失败。 */
    deviceCertAmbiguous() {
      return this.hasAmbiguousCandidate(TYPE_DEVICE_IDENTITY, this.platformGbId)
    },
    /** 上级平台证书同上。 */
    platformCertAmbiguous() {
      return this.hasAmbiguousCandidate(TYPE_TRUSTED_PLATFORM, this.value && this.value.serverGBId)
    },
    /**
     * 主题里使用的密码模块 ID，取自后端配置 `gb35114.module-id`
     * （附录 A 表 A.1 第 6 项 / 附录 B：22 位十进制数字）。
     *
     * <p>没有硬件密码模块时用 22 个 0 占位；具体填什么由运维按现场备案决定，
     * 故做成配置项而非写死。后端未下发时回退到 22 个 0，与后端
     * `MODULE_ID_PLACEHOLDER` 保持一致。
     */
    defaultModuleId() {
      return (this.policy && this.policy.moduleId) || '0'.repeat(22)
    },
    /**
     * 本平台在该上级处的默认主题：设备国标编号_密码模块 ID。
     *
     * <p>国标 ID 优先取「SIP 认证用户名」—— 那才是上级用来认本平台身份的字段；
     * 页面上它由「设备国标编号」自动带出（`deviceGBIdChange`），但用户可以单独改，
     * 改了之后以用户填的为准，故先取 username 再退回 deviceGBId / serverGBId。
     * 取不到时退回 `NULL_全0`（标准里空段写 NULL），至少不生成格式上说不通的串。
     */
    defaultCsrSubjectCn() {
      const gbId = this.platformGbId || 'NULL'
      return gbId + '_' + this.defaultModuleId
    },
    /** 本平台在该上级处的国标 ID：SIP 认证用户名 → 设备国标编号 → 上级服务国标编码。 */
    platformGbId() {
      const v = this.value || {}
      return String(v.username || v.deviceGBId || v.serverGBId || '').trim()
    }
  },
  created() {
    this.loadCertList()
    // 主题默认值要用到 moduleId，先拉策略；失败时按 22 个 0 渲染，不影响本页其余功能
    getCertPolicy().then(res => {
      const data = (res && res.data) || {}
      this.policy = {
        moduleId: data.moduleId || '',
        verifyUpstreamCertChain: data.verifyUpstreamCertChain !== false
      }
    }).catch(() => {})
  },
  methods: {
    /**
     * 该证书的签发者是否未导入本平台（即证书链校验会不通过）。
     *
     * <p>判据与「国密证书管理」页「签发方式」列逐条一致，避免同一件事两处口径不同：
     * 已签发的证书（有 certPem）、非自签、且没有关联到任何 CA（caId 为空）。
     * 自签不算 —— 它自己就是链的根，提示「签发者未导入」只会误导。
     */
    issuerUnknown(cert) {
      return !!(cert && cert.certPem && !cert.selfSigned && !cert.caId)
    },
    /** 证书是否已过有效期（后端存 'yyyy-MM-dd HH:mm:ss'，Safari 需替换空格为 T） */
    certExpired(cert) {
      if (!cert || !cert.notAfter) return false
      const t = Date.parse(String(cert.notAfter).replace(' ', 'T'))
      return !isNaN(t) && t < Date.now()
    },
    loadCertList: function() {
      listCert()
        .then(res => {
          this.certList = (res && res.data) || []
          this.autoBindFallbacks()
        })
        .catch(error => {
          console.log(error)
        })
    },
    /**
     * 把「没绑定、但按国标 ID 能唯一定位」的证书自动绑定到本上级。
     *
     * <p>这两个证书槽里的证书本来就只适用于这一个上级（设备证书按本上级的
     * 认证用户名申请、上级证书从该上级导出），归属不该停留在"运行期靠匹配"
     * 的隐式状态 —— 打开编辑页即替用户把关系写进 wvp_platform，之后新增上级
     * 或重复导入都不会再分走它。多张无法唯一定位时不猜，仍由 ambiguity 提示。
     */
    autoBindFallbacks() {
      if (!this.isEdit || !this.isGb35114Way) return
      const jobs = []
      if (!this.deviceCert) {
        const c = this.resolveFallback(TYPE_DEVICE_IDENTITY, this.platformGbId)
        if (c) jobs.push({ type: TYPE_DEVICE_IDENTITY, field: 'deviceCertId', cert: c })
      }
      if (!this.platformCert) {
        const c = this.resolveFallback(TYPE_TRUSTED_PLATFORM, this.value && this.value.serverGBId)
        if (c) jobs.push({ type: TYPE_TRUSTED_PLATFORM, field: 'platformCertId', cert: c })
      }
      jobs.forEach(j => {
        bindCertToPlatform(this.value.id, j.type, j.cert.id)
          .then(() => {
            // 只在仍无绑定时回写，避免覆盖用户在此期间的显式选择
            if (!this.value[j.field]) this.$set(this.value, j.field, j.cert.id)
          })
          .catch(error => {
            console.log(error)
          })
      })
    },
    /** 按 id 从证书列表取一张（找不到返回 null）。 */
    findCert(id) {
      if (id === null || id === undefined) return null
      return (this.certList || []).find(c => c.id === id) || null
    },
    /**
     * 复现后端 {@code resolveByType} 的兜底解析：按国标 ID 精确匹配，否则唯一候选。
     *
     * <p>只在「没有显式绑定」时才该用它 —— 显式绑定优先，后端也是这个顺序。
     */
    resolveFallback(type, gbId) {
      const candidates = (this.certList || []).filter(c => c.type === type && !c.revoked)
      if (candidates.length === 0) return null
      const key = String(gbId || '').trim()
      if (key) {
        const exact = candidates.find(c => c.gbId === key)
        if (exact) return exact
      }
      // 多候选时后端拒绝猜测并返回 null，页面照做 —— 这里显示一张「可能不是它」的证书，
      // 会让人以为绑定已经成立，而实际注册时拿不到证书
      return candidates.length === 1 ? candidates[0] : null
    },
    /** 是否处于「有候选、但国标 ID 匹配不上且不止一张」的状态（后端会拒绝猜测）。 */
    hasAmbiguousCandidate(type, gbId) {
      const candidates = (this.certList || []).filter(c => c.type === type && !c.revoked)
      if (candidates.length <= 1) return false
      const key = String(gbId || '').trim()
      return !key || !candidates.some(c => c.gbId === key)
    },
    /**
     * 打开「创建 CSR」对话框。
     *
     * <p>主题默认填「设备国标编号_密码模块 ID」—— 密码模块 ID 取自配置 `gb35114.module-id`
     * （留空即 22 个 0）。默认值只是默认值：接入多个上级时本平台可能需要另编编码防冲突，
     * 因此主题与其余 DN 字段都可直接改。
     */
    openDeviceCsr() {
      this.csrDialog = {
        visible: true, loading: false,
        form: {
          subjectCn: this.defaultCsrSubjectCn,
          gbId: this.platformGbId,
          country: 'CN', province: '', locality: '',
          organization: '', organizationalUnit: '', remark: '', validityDays: 3650
        }
      }
      this.$nextTick(() => { if (this.$refs.csrForm) this.$refs.csrForm.clearValidate() })
    },
    /** 主题变更时同步国标 ID 列（取「_」前的部分，供落库与列表显示）。 */
    syncCsrGbIdFromCn(value) {
      this.csrDialog.form.gbId = String(value || '').split('_')[0].trim()
    },
    /**
     * 主题里密码模块 ID 段的合规性提示（附录 A 表 A.1 / 附录 B）。
     *
     * <p>与「国密证书管理」页的同名方法一致：点「生成」之前先提示并中止，避免一次失败往返。
     * 空段与 `NULL` 都是标准认可的写法，放行。
     */
    checkSubjectModuleId(subjectCn) {
      const parts = String(subjectCn || '').split('_')
      if (parts.length < 2) {
        return true
      }
      const m = (parts[1] || '').trim()
      if (!m || m.toUpperCase() === 'NULL' || /^\d{22}$/.test(m)) {
        return true
      }
      this.$message.warning('主题中密码模块 ID 段须为 22 位十进制数字（附录 B），当前为：' + m)
      return false
    },
    /**
     * 提交 CSR 表单，并立即把返回的 id 写进 value.deviceCertId。
     *
     * <p>先落库再写引用：这样中途取消表单也只会留下一张能在「国密证书管理」页看到的
     * 待签发证书，不会产生悬空引用。证书要交上级签发，回填后才可用。
     */
    submitDeviceCsr() {
      this.$refs.csrForm.validate(valid => {
        if (!valid) return
        const f = this.csrDialog.form
        if (!this.checkSubjectModuleId(f.subjectCn)) return
        this.csrDialog.loading = true
        createCsr({
          type: TYPE_DEVICE_IDENTITY,
          gbId: f.gbId,
          subjectCn: f.subjectCn || f.gbId,
          country: f.country,
          province: f.province,
          locality: f.locality,
          organization: f.organization,
          organizationalUnit: f.organizationalUnit,
          remark: f.remark
        }, f.validityDays)
          .then(res => {
            const id = res && res.data && res.data.id
            this.csrDialog.visible = false
            this.$message.success('CSR 已生成，请导出后交上级签发，再回到这里点「回填」')
            // 绑定即时落库，不等点「保存」：本页拿到的 value 就是列表行对象本身，
            // 只改内存会让人以为绑上了，一刷新就没了。
            this.bindCert(TYPE_DEVICE_IDENTITY, 'deviceCertId', id)
          })
          .catch(error => { console.log(error) })
          .finally(() => { this.csrDialog.loading = false })
      })
    },
    /** 导出待签发记录的 CSR（交付上级 CA 用；CSR 不含私钥）。 */
    downloadCsrFile(cert) {
      downloadCsr(cert.id).then(res => {
        this.saveBlob(res, 'csr-' + cert.id + '.csr')
      }).catch(error => { console.log(error) })
    },
    /** 导出证书 PEM。 */
    downloadCertFile(cert) {
      downloadCert(cert.id).then(res => {
        this.saveBlob(res, 'cert-' + cert.id + '.pem')
      }).catch(error => { console.log(error) })
    },
    saveBlob(res, filename) {
      const blob = new Blob([res], { type: 'application/octet-stream' })
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      a.click()
      window.URL.revokeObjectURL(url)
    },
    /** 打开「回填」对话框：把上级签发好的证书写回这条待签发记录。 */
    openCompletePending(cert) {
      this.completeDialog = { visible: true, loading: false, id: cert.id, subjectCn: cert.subjectCn }
      this.completeCertFile = null
      if (this.$refs.completeCertFile) this.$refs.completeCertFile.value = ''
    },
    onCompleteFileChange(event) {
      this.completeCertFile = event.target.files[0]
    },
    submitCompletePending() {
      if (!this.completeCertFile) {
        this.$message.warning('请选择证书文件')
        return
      }
      this.completeDialog.loading = true
      completePendingCsr(this.completeDialog.id, this.completeCertFile)
        .then(() => {
          this.completeDialog.visible = false
          this.$message.success('回填成功')
          this.loadCertList()
        })
        .catch(error => { console.log(error) })
        .finally(() => { this.completeDialog.loading = false })
    },
    /** 打开「导入上级证书」对话框（仅公钥，验 sign2）。 */
    openPeerImport() {
      this.peerImportDialog = { visible: true, loading: false, gbId: this.value.serverGBId, remark: '' }
      this.peerCertFile = null
      if (this.$refs.peerCertFile) this.$refs.peerCertFile.value = ''
    },
    onPeerFileChange(event) {
      this.peerCertFile = event.target.files[0]
    },
    submitPeerImport() {
      if (!this.peerCertFile) {
        this.$message.warning('请选择证书文件')
        return
      }
      this.peerImportDialog.loading = true
      importPeer({
        type: TYPE_TRUSTED_PLATFORM,
        gbId: this.peerImportDialog.gbId,
        remark: this.peerImportDialog.remark
      }, this.peerCertFile)
        .then(res => {
          const id = res && res.data && res.data.id
          this.peerImportDialog.visible = false
          // 签发者 CA 未导入时后端会给一句提示（不拦导入）。这里用 notify 说清"刚发生了什么"，
          // 常驻的告警由证书槽下方的 issuerUnknown 判定负责 —— 通知会消失，告警不会。
          const warn = res && res.data && res.data.importWarning
          if (warn) {
            this.$notify({ title: '导入成功，但有一处需要处理', message: warn, type: 'warning', duration: 0 })
          }
          // 绑定即时落库，与「创建 CSR」同理
          this.bindCert(TYPE_TRUSTED_PLATFORM, 'platformCertId', id)
        })
        .catch(error => { console.log(error) })
        .finally(() => { this.peerImportDialog.loading = false })
    },
    /** 打开「导入 CA」对话框（受信任的 CA，仅公钥）。本页只导不删。 */
    openCaImport() {
      this.caImportDialog = { visible: true, loading: false }
      this.caCertFile = null
      if (this.$refs.caCertFile) this.$refs.caCertFile.value = ''
    },
    onCaFileChange(event) {
      this.caCertFile = event.target.files[0]
    },
    submitCaImport() {
      if (!this.caCertFile) {
        this.$message.warning('请选择 CA 证书文件')
        return
      }
      this.caImportDialog.loading = true
      importCa({ type: TYPE_TRUSTED_CA, certFile: this.caCertFile })
        .then(() => {
          this.caImportDialog.visible = false
          this.$message.success('CA 导入成功')
        })
        .catch(error => { console.log(error) })
        .finally(() => { this.caImportDialog.loading = false })
    },
    /**
     * 把证书绑定到本上级（{@code certId} 为空表示解绑），并即时落库。
     *
     * <p>绑定是<b>本上级专属</b>的关系：同一个平台可以接入多个上级，每个上级各有一张
     * 本平台的客户端证书、一张上级的服务端证书。这个归属必须落到 {@code wvp_platform} 的
     * {@code device_cert_id} / {@code platform_cert_id} 上 —— 不写的话运行期只能按国标 ID
     * 反查兜底，接入第二个上级就退化成「拒绝猜测」，页面上也无从回显绑的是哪张。
     *
     * <p>刻意不走整行「保存」：本页的 {@code value} 就是列表行对象本身，只改内存会让人
     * 以为绑上了、一刷新就没了；而整行保存还要过唯一键等前置校验，失败时绑定跟着一起丢。
     */
    bindCert(type, field, certId) {
      if (!certId) return
      return bindCertToPlatform(this.value.id, type, certId)
        .then(() => {
          this.$set(this.value, field, certId)
          this.$message.success('已绑定到本上级')
          this.loadCertList()
        })
        .catch(error => {
          // 绑定没落库就绝不能只在内存里显示成功 —— 那正是这次要修的毛病
          console.log(error)
          this.$message.error('绑定失败，请重试')
        })
    },
    /**
     * 删除本上级正在使用的证书。
     *
     * <p>证书此刻仍被<b>本</b> platform 行引用，直接删会被引用守卫拒绝，
     * 因此走后端的 unbindAndDelete：先置空引用列再删。若还被别的平台或设备引用，照旧拒绝并点名。
     */
    unbindAndDelete(cert, field) {
      this.$confirm('确认删除该证书？本地身份证书的私钥将一并删除，且不可恢复。', '提示', {
        confirmButtonText: '确定', cancelButtonText: '取消', type: 'warning'
      }).then(() => {
        return unbindAndDeleteCert(cert.id)
      }).then(() => {
        this.$set(this.value, field, null)
        this.$message.success('已删除')
        this.loadCertList()
      }).catch(error => { console.log(error) })
    },
    onSubmit: function() {
      this.saveLoading = true
      if (this.value.id) {
        this.$store.dispatch('platform/update', this.value)
          .then(data => {
            this.$message({
              showClose: true,
              message: '保存成功',
              type: 'success'
            })
            if (this.closeEdit) {
              this.closeEdit()
            }
          })
          .catch(error => {
            console.log(error)
          })
          .finally(() => {
            this.saveLoading = false
          })
      } else {
        this.$store.dispatch('platform/add', this.value)
          .then(data => {
            this.$message({
              showClose: true,
              message: '保存成功',
              type: 'success'
            })
            if (this.closeEdit) {
              this.closeEdit()
            }
          })
          .catch(error => {
            console.log(error)
          })
          .finally(() => {
            this.saveLoading = false
          })
      }
    },
    serverGBIdChange: function() {
      if (this.value.serverGBId.length > 10) {
        this.value.serverGBDomain = this.value.serverGBId.substr(0, 10)
      }
    },
    deviceGBIdChange: function() {
      this.value.username = this.value.deviceGBId
    },
    checkExpires: function() {
      if (this.value.enable && this.value.expires === '0') {
        this.value.expires = '3600'
      }
    },
    rtcpCheckBoxChange: function(result) {
      if (result) {
        this.$message({
          showClose: true,
          message: '开启RTCP保活需要上级平台支持，可以避免无效推流',
          type: 'warning'
        })
      }
    },
    deviceGBIdExit: async function(deviceGbId) {
      let result = false
      await this.$store.dispatch('platform/exit', deviceGbId)
        .then((data) => {
          result = data
        }).catch((error) => {
          console.log(error)
        })
      return result
    },
    close: function() {
      this.closeEdit()
    }
  }
}
</script>

<style scoped>
/* 新增页选 GB35114 注册方式时的提示条 */
.gb35114-create-tip {
  margin-bottom: 12px;
}
/* VKEK 更新周期上限提示（6.14.3）：与证书槽说明同级的辅助文字，不抢主信息 */
.gb35114-vkek-tip {
  font-size: 12px;
  color: #909399;
  line-height: 1.6;
  margin-top: 4px;
}
/* 证书槽：空态是按钮 + 说明；已有证书时是摘要芯片 + 操作按钮，两行排布 */
.cert-slot {
  line-height: 1.8;
}
.cert-actions {
  margin-top: 6px;
}
.cert-slot-hint {
  font-size: 12px;
  color: #909399;
  margin-left: 8px;
}
/* 真会出问题（多候选无法定位，注册必然失败）才用告警色 */
.cert-fallback {
  font-size: 12px;
  color: #e6a23c;
  line-height: 1.8;
  margin-top: 4px;
}
.hint {
  font-size: 12px;
  color: #909399;
  margin: 8px 0 12px;
  line-height: 1.6;
}
/* 表单控件右侧的辅助说明（与「国密证书管理」页同名同款） */
.hint-inline {
  font-size: 12px;
  color: #909399;
  margin-left: 8px;
}
</style>
