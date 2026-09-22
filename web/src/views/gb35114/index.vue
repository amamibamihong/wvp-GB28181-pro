<template>
  <div class="app-container">
    <el-alert
      type="info"
      :closable="false"
      show-icon
      class="tip"
      title="证书按用途分区管理。私钥不在页面上下载：本地身份证书的私钥与 CSR 存于同一条记录，仅在服务端签名时内部使用，删除记录即一并删除私钥。"
    />
    <el-alert
      :type="policy.rejectExpiredCert ? 'warning' : 'info'"
      :closable="false"
      show-icon
      class="tip"
      :title="policy.rejectExpiredCert
        ? '当前策略：拒绝已过期的证书（gb35114.reject-expired-cert=true）—— 过期证书会导致设备/级联注册被拒。'
        : '当前策略：不拒绝已过期的证书（gb35114.reject-expired-cert=false）—— 过期仅在下方标出，不影响接入；请看到「已过期」后及时吊销并重新颁发。'"
    />

    <el-tabs v-model="activeTab" type="card">
      <!-- ==================== 1. 本地 CA ==================== -->
      <el-tab-pane label="本地CA" name="localCa">
        <el-form :inline="true" size="mini" class="toolbar">
          <el-form-item>
            <el-button type="primary" icon="el-icon-plus" size="mini" @click="openCaGenerate">生成本地根 CA</el-button>
            <el-button type="warning" icon="el-icon-upload2" size="mini" @click="openCaImport('LOCAL_CA')">导入本地 CA</el-button>
            <el-button icon="el-icon-refresh-right" size="mini" circle @click="loadCaList" />
          </el-form-item>
        </el-form>
        <div class="hint">
          本地 CA 私钥留在本平台，用于签发本地服务端/客户端证书及下级客户端证书。<br>
          <b>本地 CA 只保留一份</b>：已存在时「生成 / 导入本地 CA」会被拒绝，需先删除旧的
          （仍被证书引用的删不掉）。上级 CA 可有多份，对应多个上级平台。<br>
          摄像头等设备要求「导入服务端 CA」时，点操作列的<b>导出</b>取走本 CA 证书（.crt）交给设备导入。
        </div>

        <el-table :data="localCaList" v-loading="caLoading" size="small" border style="width: 100%">
          <el-table-column prop="id" label="ID" width="60" />
          <el-table-column label="主题（CN）" min-width="220">
            <template v-slot:default="scope">
              <el-tooltip :disabled="!subjectTip(scope.row)" :content="subjectTip(scope.row)" placement="top">
                <span class="cell-ellipsis">{{ scope.row.subjectCn || '-' }}</span>
              </el-tooltip>
            </template>
          </el-table-column>
          <el-table-column prop="notAfter" label="失效时间" min-width="170" />
          <el-table-column prop="remark" label="备注" min-width="160" show-overflow-tooltip />
          <el-table-column label="操作" width="140" fixed="right">
            <template v-slot:default="scope">
              <el-button type="text" size="mini" @click="downloadCaFile(scope.row)">导出</el-button>
              <el-button type="text" size="mini" style="color: #f56c6c" @click="confirmDeleteCa(scope.row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <!-- ==================== 2. 本地服务端证书 ==================== -->
      <el-tab-pane label="本地服务端证书" name="serverIdentity">
        <el-form :inline="true" size="mini" class="toolbar">
          <el-form-item>
            <el-button type="primary" icon="el-icon-plus" size="mini" @click="openIdentity('SERVER_IDENTITY')">创建 CSR</el-button>
            <el-button icon="el-icon-upload2" size="mini" @click="openIdentityImport('SERVER_IDENTITY')">导入（证书+私钥）</el-button>
            <el-button type="success" icon="el-icon-magic-stick" size="mini" @click="openSelfSigned('SERVER_IDENTITY')">自签生成</el-button>
            <el-button icon="el-icon-refresh-right" size="mini" circle @click="loadCertList" />
          </el-form-item>
        </el-form>
        <div class="hint">
          本平台作 UAS，对 sign2 签名。私钥留在本平台，不可下载。<br />
          <b>平台只保留一组服务端密钥对</b>：已存在未吊销的服务端证书时，「创建 CSR」与「自签生成」
          会被拒绝 —— 多组密钥并存时，设备绑定的是哪一组无从判断，选错会让设备验 sign2 失败而平台日志一切正常。<br />
          换发请用<b>「同密钥再签」</b>（公钥不变，设备无需重新导入），可派生多张不同有效期/DN/签发者的证书，
          它们对设备完全等价、可互换。确需更换密钥（如私钥泄露）时，先吊销该组全部证书，再新建。
        </div>

        <el-table :data="serverIdentityList" v-loading="certLoading" size="small" border style="width: 100%">
          <el-table-column prop="id" label="ID" width="60" />
          <el-table-column label="主题（CN）" min-width="170">
            <template v-slot:default="scope">
              <el-tooltip :disabled="!subjectTip(scope.row)" :content="subjectTip(scope.row)" placement="top">
                <span class="cell-ellipsis">{{ scope.row.subjectCn || '-' }}</span>
              </el-tooltip>
            </template>
          </el-table-column>
          <el-table-column prop="gbId" label="本平台编码" min-width="170">
            <template v-slot:default="scope">{{ scope.row.gbId || '-' }}</template>
          </el-table-column>
          <el-table-column label="签发方式" min-width="200">
            <template v-slot:default="scope">
              <el-tooltip :content="issuerTip(scope.row)" placement="top">
                <el-tag size="mini" :type="issuerTagType(scope.row)">{{ issuerText(scope.row) }}</el-tag>
              </el-tooltip>
            </template>
          </el-table-column>
          <el-table-column label="状态" width="110">
            <template v-slot:default="scope">
              <el-tag v-if="scope.row.revoked" size="mini" type="danger">已吊销</el-tag>
              <el-tag v-else-if="!scope.row.certPem" size="mini" type="warning">待签发</el-tag>
              <el-tooltip v-else-if="expiryState(scope.row) === 'expired'"
                          :content="expiredTip(
                            '已过期：该证书不能用于签 sign2，绑定它的设备将被拒绝注册',
                            '已过期：当前策略不拒绝过期证书，仍可用于签 sign2；建议用「同密钥再签」换发')"
                          placement="top">
                <el-tag size="mini" type="danger">已过期</el-tag>
              </el-tooltip>
              <el-tooltip v-else-if="expiryState(scope.row) === 'soon'"
                          :content="'即将过期（剩余 ' + daysLeft(scope.row) + ' 天），请提前用「同密钥再签」换发'"
                          placement="top">
                <el-tag size="mini" type="warning">即将过期</el-tag>
              </el-tooltip>
              <!-- 有效是常态，不再出 tag，避免整列都是绿色噪音 -->
              <span v-else style="color: #c0c4cc">-</span>
            </template>
          </el-table-column>
          <el-table-column label="公钥指纹" min-width="150">
            <template v-slot:default="scope">
              <el-tooltip v-if="scope.row.keyFingerprint"
                          :content="'公钥指纹 ' + scope.row.keyFingerprint + '（相同即同一签名身份，证书可互换）'">
                <span style="font-family: monospace">{{ scope.row.keyFingerprint.slice(0, 12) }}…</span>
              </el-tooltip>
              <span v-else style="color: #c0c4cc">-</span>
            </template>
          </el-table-column>
          <el-table-column label="失效时间" min-width="170">
            <template v-slot:default="scope">
              <span :style="expiryState(scope.row) === 'expired' ? 'color:#f56c6c'
                             : expiryState(scope.row) === 'soon' ? 'color:#e6a23c' : ''">
                {{ scope.row.notAfter || '-' }}
                <template v-if="expiryText(scope.row)">
                  （{{ expiryText(scope.row) }}）
                </template>
              </span>
            </template>
          </el-table-column>
          <el-table-column prop="remark" label="备注" min-width="120" show-overflow-tooltip />
          <el-table-column label="操作" width="380" fixed="right">
            <template v-slot:default="scope">
              <el-button v-if="!scope.row.certPem" type="text" size="mini" @click="downloadFile('csr', scope.row)">CSR</el-button>
              <el-button v-if="!scope.row.certPem" type="text" size="mini" style="color: #67c23a" @click="openSignPending(scope.row)">签发</el-button>
              <el-button v-if="!scope.row.certPem" type="text" size="mini" style="color: #e6a23c" @click="openCompletePending(scope.row)">回填</el-button>
              <el-button v-if="scope.row.certPem" type="text" size="mini" @click="downloadFile('cert', scope.row)">证书</el-button>
              <el-button v-if="scope.row.certPem && scope.row.hasKey"
                         type="text" size="mini" style="color: #909399" @click="openReissue(scope.row)">同密钥再签</el-button>
              <el-button v-if="scope.row.certPem && !scope.row.revoked && !scope.row.isDefault"
                         type="text" size="mini" style="color: #409eff" @click="confirmSetDefault(scope.row)">设为默认</el-button>
              <el-button v-if="scope.row.certPem && !scope.row.revoked" type="text" size="mini" style="color: #e6a23c" @click="confirmRevoke(scope.row)">吊销</el-button>
              <el-button type="text" size="mini" style="color: #f56c6c" @click="confirmDeleteCert(scope.row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <!-- ==================== 3. 下级客户端证书 ==================== -->
      <el-tab-pane label="下级客户端证书" name="issuedDevice">
        <el-form :inline="true" size="mini" class="toolbar">
          <el-form-item>
            <el-button type="primary" icon="el-icon-plus" size="mini" @click="openIssueFromCsr">由下级 CSR 签发</el-button>
            <el-button icon="el-icon-upload2" size="mini" @click="openPeerImport('ISSUED_DEVICE')">导入下级证书（.crt）</el-button>
            <el-button icon="el-icon-refresh-right" size="mini" circle @click="loadCertList" />
          </el-form-item>
        </el-form>
        <div class="hint">
          签发给下级设备/平台的客户端证书，用于对 sign1 验签。私钥在下级，本平台不持有。<br />
          设备接入时，平台只认<b>本平台保存且有效</b>的证书：设备自报的证书若不在下表中（或已吊销），
          一律拒绝接入 —— 设备自签的证书平台没有记录，既无从判断有效性，出事时也无从追溯。外部 CA 签发的
          设备证书请先用「导入下级证书」存入本平台。<br />
          <b>吊销即刻生效</b>：设备自报的证书按公钥指纹反查本表，命中已吊销记录即拒绝接入。
        </div>

        <el-table :data="issuedDeviceList" v-loading="certLoading" size="small" border style="width: 100%">
          <el-table-column prop="id" label="ID" width="60" />
          <el-table-column prop="gbId" label="下级客户端编码" min-width="180">
            <template v-slot:default="scope">{{ scope.row.gbId || '-' }}</template>
          </el-table-column>
          <el-table-column label="关联设备" min-width="180" show-overflow-tooltip>
            <template v-slot:default="scope">
              <el-tooltip v-if="scope.row.relatedDeviceName"
                          :content="'本平台为该设备签发的下级客户端证书：' + scope.row.relatedDeviceName
                            + '（' + scope.row.gbId + '）'"
                          placement="top">
                <el-button type="text" size="mini" @click="goDeviceList()">
                  {{ scope.row.relatedDeviceName }}
                </el-button>
              </el-tooltip>
              <el-tooltip v-else
                          content="本平台的设备列表中还没有这个国标 ID 的设备；证书可能是提前签发的，或设备尚未接入"
                          placement="top">
                <span style="color: #c0c4cc">未接入</span>
              </el-tooltip>
            </template>
          </el-table-column>
          <el-table-column label="主题（CN）" min-width="170">
            <template v-slot:default="scope">
              <el-tooltip :disabled="!subjectTip(scope.row)" :content="subjectTip(scope.row)" placement="top">
                <span class="cell-ellipsis">{{ scope.row.subjectCn || '-' }}</span>
              </el-tooltip>
            </template>
          </el-table-column>
          <el-table-column label="签发方式" min-width="200">
            <template v-slot:default="scope">
              <el-tooltip :content="issuerTip(scope.row)" placement="top">
                <el-tag size="mini" :type="issuerTagType(scope.row)">{{ issuerText(scope.row) }}</el-tag>
              </el-tooltip>
            </template>
          </el-table-column>
          <el-table-column label="状态" width="110">
            <template v-slot:default="scope">
              <el-tag v-if="scope.row.revoked" size="mini" type="danger">已吊销</el-tag>
              <el-tooltip v-else-if="expiryState(scope.row) === 'expired'"
                          :content="expiredTip(
                            '已过期：设备持此证书将无法接入，需重新签发并换发到设备',
                            '已过期：当前策略不拒绝过期证书，设备仍可接入；建议尽快续签并换发到设备')"
                          placement="top">
                <el-tag size="mini" type="danger">已过期</el-tag>
              </el-tooltip>
              <el-tooltip v-else-if="expiryState(scope.row) === 'soon'"
                          :content="'即将过期（剩余 ' + daysLeft(scope.row) + ' 天），请提前续签'"
                          placement="top">
                <el-tag size="mini" type="warning">即将过期</el-tag>
              </el-tooltip>
              <span v-else style="color: #c0c4cc">-</span>
            </template>
          </el-table-column>
          <el-table-column prop="notAfter" label="失效时间" min-width="170" />
          <el-table-column prop="remark" label="备注" min-width="120" show-overflow-tooltip />
          <el-table-column label="操作" width="160" fixed="right">
            <template v-slot:default="scope">
              <el-button type="text" size="mini" @click="downloadFile('cert', scope.row)">证书</el-button>
              <el-button v-if="!scope.row.revoked" type="text" size="mini" style="color: #e6a23c" @click="confirmRevoke(scope.row)">吊销</el-button>
              <el-button type="text" size="mini" style="color: #f56c6c" @click="confirmDeleteCert(scope.row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <!-- ==================== 4. 本地客户端证书 ==================== -->
      <el-tab-pane label="本地客户端证书" name="deviceIdentity">
        <el-form :inline="true" size="mini" class="toolbar">
          <el-form-item>
            <el-button type="primary" icon="el-icon-plus" size="mini" @click="openIdentity('DEVICE_IDENTITY')">创建 CSR</el-button>
            <el-button icon="el-icon-upload2" size="mini" @click="openIdentityImport('DEVICE_IDENTITY')">导入（证书+私钥）</el-button>
            <el-button icon="el-icon-refresh-right" size="mini" circle @click="loadCertList" />
          </el-form-item>
        </el-form>
        <div class="hint">
          本平台作 UAC（含国标级联作下级接入上级），对 sign1 签名。<b>这张证书必须由上级签发</b>：
          本平台作客户端，上级作服务端，只有上级自己签发并留存的证书它才认。<br />
          流程：<b>创建 CSR</b> → 在列表中导出 CSR 交给上级 → 上级签发后回到列表点<b>回填</b>。
          私钥留在本平台，不可下载。<br />
          此处<b>不提供「自签生成」与「本地签发」</b>：本平台自签或用本地 CA 签出来的证书，
          上级那边没有签发记录，接入必然被拒 —— 而失败只出现在上级，本平台日志一切正常，排查容易跑偏。<br />
          接入多个上级时，每个上级各签一张本平台的客户端证书，并在
          <b>国标级联 → 编辑上级平台</b> 的「国密设备证书」下拉里绑定；「关联平台」列即显示该绑定关系。
        </div>

        <el-table :data="deviceIdentityList" v-loading="certLoading" size="small" border style="width: 100%">
          <el-table-column prop="id" label="ID" width="60" />
          <el-table-column prop="gbId" label="本平台编码" min-width="180">
            <template v-slot:default="scope">{{ scope.row.gbId || '-' }}</template>
          </el-table-column>
          <el-table-column label="关联平台" min-width="180" show-overflow-tooltip>
            <template v-slot:default="scope">
              <el-tooltip v-if="scope.row.relatedPlatformName"
                          :content="'该上级平台在级联配置里绑定了本证书（国密设备证书），用于向上注册时签 sign1：'
                            + scope.row.relatedPlatformName"
                          placement="top">
                <el-button type="text" size="mini" @click="goPlatformList()">
                  {{ scope.row.relatedPlatformName }}
                </el-button>
              </el-tooltip>
              <el-tooltip v-else
                          content="没有级联平台显式绑定本证书。平台注册时会回退到全局 gb35114.device-cert-id 配置"
                          placement="top">
                <span style="color: #c0c4cc">未绑定</span>
              </el-tooltip>
            </template>
          </el-table-column>
          <el-table-column label="主题（CN）" min-width="170">
            <template v-slot:default="scope">
              <el-tooltip :disabled="!subjectTip(scope.row)" :content="subjectTip(scope.row)" placement="top">
                <span class="cell-ellipsis">{{ scope.row.subjectCn || '-' }}</span>
              </el-tooltip>
            </template>
          </el-table-column>
          <el-table-column label="签发方式" min-width="200">
            <template v-slot:default="scope">
              <el-tooltip :content="issuerTip(scope.row)" placement="top">
                <el-tag size="mini" :type="issuerTagType(scope.row)">{{ issuerText(scope.row) }}</el-tag>
              </el-tooltip>
            </template>
          </el-table-column>
          <el-table-column label="状态" width="110">
            <template v-slot:default="scope">
              <el-tag v-if="scope.row.revoked" size="mini" type="danger">已吊销</el-tag>
              <el-tag v-else-if="!scope.row.certPem" size="mini" type="warning">待签发</el-tag>
              <el-tooltip v-else-if="expiryState(scope.row) === 'expired'"
                          :content="expiredTip(
                            '已过期：该客户端不能再接入本平台，需由上级重新签发后回填',
                            '已过期：当前策略不拒绝过期证书，仍可向上级注册；建议尽快由上级重新签发后回填')"
                          placement="top">
                <el-tag size="mini" type="danger">已过期</el-tag>
              </el-tooltip>
              <el-tooltip v-else-if="expiryState(scope.row) === 'soon'"
                          :content="'即将过期（剩余 ' + daysLeft(scope.row) + ' 天），请提前续签'"
                          placement="top">
                <el-tag size="mini" type="warning">即将过期</el-tag>
              </el-tooltip>
              <span v-else style="color: #c0c4cc">-</span>
            </template>
          </el-table-column>
          <el-table-column label="失效时间" min-width="170">
            <template v-slot:default="scope">
              <span :style="expiryState(scope.row) === 'expired' ? 'color:#f56c6c'
                             : expiryState(scope.row) === 'soon' ? 'color:#e6a23c' : ''">
                {{ scope.row.notAfter || '-' }}
                <template v-if="expiryText(scope.row)">（{{ expiryText(scope.row) }}）</template>
              </span>
            </template>
          </el-table-column>
          <el-table-column prop="remark" label="备注" min-width="120" show-overflow-tooltip />
          <el-table-column label="操作" width="180" fixed="right">
            <template v-slot:default="scope">
              <el-button v-if="!scope.row.certPem" type="text" size="mini" @click="downloadFile('csr', scope.row)">CSR</el-button>
              <el-button v-if="!scope.row.certPem" type="text" size="mini" style="color: #e6a23c" @click="openCompletePending(scope.row)">回填</el-button>
              <el-button v-if="scope.row.certPem" type="text" size="mini" @click="downloadFile('cert', scope.row)">证书</el-button>
              <el-button v-if="scope.row.certPem && !scope.row.revoked" type="text" size="mini" style="color: #e6a23c" @click="confirmRevoke(scope.row)">吊销</el-button>
              <el-button type="text" size="mini" style="color: #f56c6c" @click="confirmDeleteCert(scope.row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <!-- ==================== 5. 上级服务端证书 ==================== -->
      <el-tab-pane label="上级服务端证书" name="trustedPlatform">
        <el-form :inline="true" size="mini" class="toolbar">
          <el-form-item>
            <el-button icon="el-icon-upload2" size="mini" @click="openPeerImport('TRUSTED_PLATFORM')">导入上级证书</el-button>
            <el-button type="warning" icon="el-icon-upload2" size="mini" @click="openCaImport('TRUSTED_CA')">导入上级 CA</el-button>
            <el-button icon="el-icon-refresh-right" size="mini" circle @click="refreshAll" />
          </el-form-item>
        </el-form>
        <div class="hint">
          上级平台的服务端证书，仅含公钥，用于对上级下发的 sign2 验签。本平台不持有其私钥。<br />
          接入多个上级时，每个上级各导入一张，并在 <b>国标级联 → 编辑上级平台</b> 的
          「上级平台证书」下拉里绑定；「关联平台」列即显示该绑定关系。
        </div>

        <el-table :data="trustedPlatformList" v-loading="certLoading" size="small" border style="width: 100%">
          <el-table-column prop="id" label="ID" width="60" />
          <el-table-column prop="gbId" label="上级平台编码" min-width="180">
            <template v-slot:default="scope">{{ scope.row.gbId || '-' }}</template>
          </el-table-column>
          <el-table-column label="关联平台" min-width="180" show-overflow-tooltip>
            <template v-slot:default="scope">
              <el-tooltip v-if="scope.row.relatedPlatformName"
                          :content="'该上级平台在级联配置里绑定了本证书（上级平台证书），用于验其下发的 sign2：'
                            + scope.row.relatedPlatformName"
                          placement="top">
                <el-button type="text" size="mini" @click="goPlatformList()">
                  {{ scope.row.relatedPlatformName }}
                </el-button>
              </el-tooltip>
              <el-tooltip v-else
                          content="没有级联平台显式绑定本证书。验签时会回退到全局 gb35114.platform-cert-id 配置"
                          placement="top">
                <span style="color: #c0c4cc">未绑定</span>
              </el-tooltip>
            </template>
          </el-table-column>
          <el-table-column label="主题（CN）" min-width="170">
            <template v-slot:default="scope">
              <el-tooltip :disabled="!subjectTip(scope.row)" :content="subjectTip(scope.row)" placement="top">
                <span class="cell-ellipsis">{{ scope.row.subjectCn || '-' }}</span>
              </el-tooltip>
            </template>
          </el-table-column>
          <el-table-column label="签发方式" min-width="200">
            <template v-slot:default="scope">
              <el-tooltip :content="issuerTip(scope.row)" placement="top">
                <el-tag size="mini" :type="issuerTagType(scope.row)">{{ issuerText(scope.row) }}</el-tag>
              </el-tooltip>
            </template>
          </el-table-column>
          <el-table-column label="状态" width="110">
            <template v-slot:default="scope">
              <el-tag v-if="scope.row.revoked" size="mini" type="danger">已吊销</el-tag>
              <el-tooltip v-else-if="expiryState(scope.row) === 'expired'"
                          :content="expiredTip(
                            '已过期：本平台无法再验证上级下发的 sign2，级联注册将被拒绝',
                            '已过期：当前策略不拒绝过期证书，仍可验证上级下发的 sign2；建议提醒上级换发')"
                          placement="top">
                <el-tag size="mini" type="danger">已过期</el-tag>
              </el-tooltip>
              <el-tooltip v-else-if="expiryState(scope.row) === 'soon'"
                          :content="'即将过期（剩余 ' + daysLeft(scope.row) + ' 天），请提前联系上级换发'"
                          placement="top">
                <el-tag size="mini" type="warning">即将过期</el-tag>
              </el-tooltip>
              <span v-else style="color: #c0c4cc">-</span>
            </template>
          </el-table-column>
          <el-table-column label="失效时间" min-width="170">
            <template v-slot:default="scope">
              <span :style="expiryState(scope.row) === 'expired' ? 'color:#f56c6c'
                             : expiryState(scope.row) === 'soon' ? 'color:#e6a23c' : ''">
                {{ scope.row.notAfter || '-' }}
                <template v-if="expiryText(scope.row)">（{{ expiryText(scope.row) }}）</template>
              </span>
            </template>
          </el-table-column>
          <el-table-column prop="remark" label="备注" min-width="120" show-overflow-tooltip />
          <el-table-column label="操作" width="160" fixed="right">
            <template v-slot:default="scope">
              <el-button type="text" size="mini" @click="downloadFile('cert', scope.row)">证书</el-button>
              <el-button v-if="!scope.row.revoked" type="text" size="mini" style="color: #e6a23c" @click="confirmRevoke(scope.row)">吊销</el-button>
              <el-button type="text" size="mini" style="color: #f56c6c" @click="confirmDeleteCert(scope.row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>

        <div class="hint" style="margin-top: 4px">
          受信上级 CA：由本平台导入留存，用于标识上级服务端证书的签发者，不可用于签发。<br>
          它不参与「是否信任」的判定（A 级握手不验证书链），仅用于把「证书 → 签发 CA → 级联平台」串起来：
          <b>关联平台</b>列显示哪个上级平台在用由本 CA 签发的证书。
        </div>
        <el-table :data="trustedCaList" v-loading="caLoading" size="small" border style="width: 100%">
          <el-table-column prop="id" label="ID" width="60" />
          <el-table-column label="主题（CN）" min-width="220">
            <template v-slot:default="scope">
              <el-tooltip :disabled="!subjectTip(scope.row)" :content="subjectTip(scope.row)" placement="top">
                <span class="cell-ellipsis">{{ scope.row.subjectCn || '-' }}</span>
              </el-tooltip>
            </template>
          </el-table-column>
          <el-table-column label="关联平台" min-width="180" show-overflow-tooltip>
            <template v-slot:default="scope">
              <el-tooltip v-if="scope.row.relatedPlatformName"
                          content="该上级平台绑定的服务端证书由本 CA 签发，因此本 CA 属于它"
                          placement="top">
                <el-button type="text" size="mini" @click="goPlatformList()">
                  {{ scope.row.relatedPlatformName }}
                </el-button>
              </el-tooltip>
              <el-tooltip v-else
                          content="本平台导入的上级服务端证书里，没有一张由本 CA 签发 —— 可能是证书还没导入，或该 CA 已不再使用"
                          placement="top">
                <span style="color: #c0c4cc">未关联</span>
              </el-tooltip>
            </template>
          </el-table-column>
          <el-table-column prop="notAfter" label="失效时间" min-width="170" />
          <el-table-column prop="remark" label="备注" min-width="140" show-overflow-tooltip />
          <el-table-column label="操作" width="80" fixed="right">
            <template v-slot:default="scope">
              <el-button type="text" size="mini" style="color: #f56c6c" @click="confirmDeleteCa(scope.row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>
    </el-tabs>

    <!-- ============ CA 生成 / 导入 ============ -->
    <el-dialog :title="caDialog.title" :visible.sync="caDialog.visible" width="520px" :close-on-click-modal="false">
      <el-form label-width="130px" size="small">
        <template v-if="caDialog.mode === 'generate'">
          <el-form-item label="主题（CN）">
            <el-input v-model="caDialog.subjectCn" placeholder="例如：GB35114 Root CA" />
          </el-form-item>
          <el-form-item label="有效期（天）">
            <el-input-number v-model="caDialog.validityDays" :min="1" :max="36500" controls-position="right" />
          </el-form-item>
          <el-form-item label="备注">
            <el-input v-model="caDialog.remark" placeholder="可选" />
          </el-form-item>
        </template>
        <template v-else>
          <el-form-item label="CA 用途">
            <el-tag size="small">{{ caDialog.purpose === 'LOCAL_CA' ? '本地 CA（持有私钥，可签发）' : '上级 CA（仅公钥，标识签发者）' }}</el-tag>
          </el-form-item>
          <el-form-item label="证书文件（.crt/.pem）">
            <input type="file" ref="caCertFile" @change="onFileChange('caCert', $event)" />
          </el-form-item>
          <el-form-item v-if="caDialog.purpose === 'LOCAL_CA'" label="私钥文件（.key/.pem）">
            <input type="file" ref="caKeyFile" @change="onFileChange('caKey', $event)" />
          </el-form-item>
          <el-form-item label="备注">
            <el-input v-model="caDialog.remark" placeholder="可选" />
          </el-form-item>
          <div class="hint">{{ caDialog.purpose === 'LOCAL_CA'
            ? '本地 CA 需含私钥才能用于签发；私钥仅加密存于服务端，不提供下载。'
            : '上级 CA 仅保存公钥，用于标识上级服务端证书的签发者，不参与「是否信任」的判定。' }}</div>
        </template>
      </el-form>
      <div slot="footer">
        <el-button size="mini" @click="caDialog.visible = false">取消</el-button>
        <el-button size="mini" type="primary" :loading="caDialog.loading" @click="submitCa">确定</el-button>
      </div>
    </el-dialog>

    <!-- ============ 创建 CSR（本地身份证书） ============ -->
    <el-dialog :title="csrDialog.title" :visible.sync="csrDialog.visible" width="620px" :close-on-click-modal="false">
      <el-form ref="csrForm" :model="csrDialog.form" :rules="formRules" label-width="130px" size="small">
        <el-form-item label="国标 ID" prop="gbId">
          <el-input v-model="csrDialog.form.gbId" placeholder="设备/平台 20 位国标编号，将自动同步为 CN"
                    @input="syncCn" />
        </el-form-item>
        <el-form-item label="主题（CN）" prop="subjectCn">
          <el-input v-model="csrDialog.form.subjectCn" placeholder="缺省与国标 ID 一致" />
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
        <el-button size="mini" type="primary" :loading="csrDialog.loading" @click="submitCsr">生成 CSR</el-button>
      </div>
    </el-dialog>

    <!-- ============ 自签生成（本地身份证书） ============ -->
    <el-dialog :title="purposeLabel(selfSignedDialog.purpose) + ' - 自签生成'" :visible.sync="selfSignedDialog.visible"
               width="620px" :close-on-click-modal="false">
      <el-form ref="selfSignedForm" :model="selfSignedDialog.form" :rules="formRules" label-width="130px" size="small">
        <el-form-item label="国标 ID" prop="gbId">
          <el-input v-model="selfSignedDialog.form.gbId" placeholder="设备/平台 20 位国标编号，将自动同步为 CN"
                    @input="syncSelfSignedCn" />
        </el-form-item>
        <el-form-item label="主题（CN）" prop="subjectCn">
          <el-input v-model="selfSignedDialog.form.subjectCn" placeholder="缺省与国标 ID 一致" />
        </el-form-item>
        <el-row>
          <el-col :span="12">
            <el-form-item label="国家（C）">
              <el-input v-model="selfSignedDialog.form.country" placeholder="CN" />
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item label="省份（ST）">
              <el-input v-model="selfSignedDialog.form.province" />
            </el-form-item>
          </el-col>
        </el-row>
        <el-row>
          <el-col :span="12">
            <el-form-item label="城市（L）">
              <el-input v-model="selfSignedDialog.form.locality" />
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item label="组织（O）">
              <el-input v-model="selfSignedDialog.form.organization" />
            </el-form-item>
          </el-col>
        </el-row>
        <el-form-item label="组织单位（OU）">
          <el-input v-model="selfSignedDialog.form.organizationalUnit" />
        </el-form-item>
        <el-form-item label="有效期（天）">
          <el-input-number v-model="selfSignedDialog.form.validityDays" :min="1" :max="36500" controls-position="right" />
          <span class="hint-inline">自签发时刻起算</span>
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="selfSignedDialog.form.remark" placeholder="可选" />
        </el-form-item>
      </el-form>
      <div class="hint">自签证书无上级 CA 可验链，仅建议在无 CA 的联调环境使用。</div>
      <div slot="footer">
        <el-button size="mini" @click="selfSignedDialog.visible = false">取消</el-button>
        <el-button size="mini" type="primary" :loading="selfSignedDialog.loading" @click="submitSelfSigned">生成</el-button>
      </div>
    </el-dialog>

    <!-- ============ 由下级 CSR 签发 ============ -->
    <el-dialog title="由下级 CSR 签发证书" :visible.sync="issueCsrDialog.visible" width="600px" :close-on-click-modal="false">
      <el-form ref="issueCsrForm" :model="issueCsrDialog.form" :rules="issueRules" label-width="130px" size="small">
        <el-form-item label="签发 CA" prop="caId">
          <el-select v-model="issueCsrDialog.form.caId" placeholder="选择本地 CA" style="width: 100%">
            <el-option v-for="ca in localCaList" :key="ca.id" :label="caLabel(ca)" :value="ca.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="下级国标 ID" prop="gbId">
          <el-input v-model="issueCsrDialog.form.gbId" placeholder="留空则从 CSR 主题 CN 自动提取" />
          <span class="hint-inline">证书主题 DN 取自 CSR，本字段仅用于登记归属</span>
        </el-form-item>
        <el-form-item label="有效期（天）">
          <el-input-number v-model="issueCsrDialog.form.validityDays" :min="1" :max="36500" controls-position="right" />
          <span class="hint-inline">自签发时刻起算</span>
        </el-form-item>
        <el-form-item label="CSR 文件">
          <el-button size="mini" icon="el-icon-upload2" @click="$refs.csrFileInput.click()">选取 .csr 文件</el-button>
          <span class="hint-inline">也可直接在下框选中粘贴 CSR 内容</span>
        </el-form-item>
        <el-form-item label="CSR 内容" prop="csrPem">
          <el-input type="textarea" :rows="7" v-model="issueCsrDialog.form.csrPem" @blur="fillGbIdFromCsr"
                    placeholder="粘贴下级提交的 -----BEGIN CERTIFICATE REQUEST----- ..." />
          <input type="file" ref="csrFileInput" accept=".csr,.pem,.txt" style="display: none" @change="onCsrFileChange" />
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="issueCsrDialog.form.remark" placeholder="可选" />
        </el-form-item>
      </el-form>
      <div class="hint">下级提交的是 <b>CSR（证书请求）</b>，只含下级公钥、不含私钥；本平台用本地 CA 对其签发，产出证书交付下级。<br>
        若对端证书已由别的 CA 签发，请改用列表上方的「导入下级证书（.crt）」。</div>
      <div slot="footer">
        <el-button size="mini" @click="issueCsrDialog.visible = false">取消</el-button>
        <el-button size="mini" type="primary" :loading="issueCsrDialog.loading" @click="submitIssueFromCsr">签发</el-button>
      </div>
    </el-dialog>

    <!-- ============ 用本地 CA 签发待签发记录 ============ -->
    <el-dialog title="用本地 CA 签发" :visible.sync="signDialog.visible" width="480px" :close-on-click-modal="false">
      <el-form label-width="130px" size="small">
        <el-form-item label="待签发记录">
          <span>{{ signDialog.subjectCn }}（#{{ signDialog.id }}）</span>
        </el-form-item>
        <el-form-item label="签发 CA">
          <el-select v-model="signDialog.caId" placeholder="选择本地 CA" style="width: 100%">
            <el-option v-for="ca in localCaList" :key="ca.id" :label="caLabel(ca)" :value="ca.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="有效期（天）">
          <el-input-number v-model="signDialog.validityDays" :min="1" :max="36500" controls-position="right" />
          <span class="hint-inline">自签发时刻起算</span>
        </el-form-item>
      </el-form>
      <div slot="footer">
        <el-button size="mini" @click="signDialog.visible = false">取消</el-button>
        <el-button size="mini" type="primary" :loading="signDialog.loading" @click="submitSignPending">签发</el-button>
      </div>
    </el-dialog>

    <!-- ============ 复用密钥对再签服务端证书 ============ -->
    <el-dialog title="复用密钥对再签服务端证书" :visible.sync="reissueDialog.visible" width="560px"
               :close-on-click-modal="false">
      <el-alert type="info" :closable="false" style="margin-bottom: 12px"
                title="私钥不变，只重新签发证书 —— 新证书公钥与源证书完全相同。">
        <div style="line-height: 1.7; font-size: 12px">
          设备只保存一个平台公钥，因此<b>同公钥的证书彼此可互换</b>：设备导入源证书或新证书
          中的任意一张，平台用同组任意一张的私钥签 sign2 都能被验过。<br />
          典型用途：延长有效期、更换主题 DN、改由 CA 签发，而<b>无需重新配置设备</b>。<br />
          也可对同一密钥对反复签发<b>不同有效期</b>的多张证书，分发给不同批次客户端 ——
          任一张到期时，平台会自动改用同组还有效的那张，客户端无感。<br />
          <b>注意：吊销不顺延。</b>同组证书共用私钥，泄露必然整组一起吊销；若吊销后还能
          自动切换到兄弟证书，吊销就失去意义。
        </div>
      </el-alert>
      <el-form label-width="130px" size="small">
        <el-form-item label="源证书">
          <span>{{ reissueDialog.sourceSubjectCn }}（#{{ reissueDialog.sourceId }}）</span>
        </el-form-item>
        <el-form-item label="主题（CN）">
          <el-input v-model="reissueDialog.profile.subjectCn" clearable placeholder="默认沿用源证书" />
        </el-form-item>
        <el-form-item label="国标 ID">
          <el-input v-model="reissueDialog.profile.gbId" clearable placeholder="平台国标编码" />
        </el-form-item>
        <el-form-item label="国家 C">
          <el-input v-model="reissueDialog.profile.country" clearable placeholder="如 CN" />
        </el-form-item>
        <el-form-item label="省份 ST">
          <el-input v-model="reissueDialog.profile.province" clearable />
        </el-form-item>
        <el-form-item label="城市 L">
          <el-input v-model="reissueDialog.profile.locality" clearable />
        </el-form-item>
        <el-form-item label="组织 O">
          <el-input v-model="reissueDialog.profile.organization" clearable />
        </el-form-item>
        <el-form-item label="组织单位 OU">
          <el-input v-model="reissueDialog.profile.organizationalUnit" clearable />
        </el-form-item>
        <el-form-item label="签发方式">
          <el-select v-model="reissueDialog.caId" clearable placeholder="自签（不选 CA）" style="width: 100%">
            <el-option v-for="ca in localCaList" :key="ca.id" :label="caLabel(ca)" :value="ca.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="有效期（天）">
          <el-input-number v-model="reissueDialog.validityDays" :min="1" :max="36500" controls-position="right" />
          <span class="hint-inline">自签发时刻起算</span>
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="reissueDialog.profile.remark" clearable />
        </el-form-item>
      </el-form>
      <div slot="footer">
        <el-button size="mini" @click="reissueDialog.visible = false">取消</el-button>
        <el-button size="mini" type="primary" :loading="reissueDialog.loading" @click="submitReissue">签发</el-button>
      </div>
    </el-dialog>

    <!-- ============ 回填外部 CA 签发的证书 ============ -->
    <el-dialog title="回填证书" :visible.sync="completeDialog.visible" width="480px" :close-on-click-modal="false">
      <el-form label-width="130px" size="small">
        <el-form-item label="待回填记录">
          <span>{{ completeDialog.subjectCn }}（#{{ completeDialog.id }}）</span>
        </el-form-item>
        <el-form-item label="证书文件">
          <input type="file" ref="completeCertFile" @change="onFileChange('completeCert', $event)" />
        </el-form-item>
      </el-form>
      <div class="hint">用于上级平台按本平台 CSR 颁发证书后的回填。服务端会校验证书公钥与本地留存私钥是否配对，不配对则拒绝。</div>
      <div slot="footer">
        <el-button size="mini" @click="completeDialog.visible = false">取消</el-button>
        <el-button size="mini" type="primary" :loading="completeDialog.loading" @click="submitCompletePending">确定</el-button>
      </div>
    </el-dialog>

    <!-- ============ 导入本地身份证书（证书 + 私钥） ============ -->
    <el-dialog title="导入本地身份证书" :visible.sync="identityImportDialog.visible" width="520px" :close-on-click-modal="false">
      <el-form label-width="130px" size="small">
        <el-form-item label="用途">
          <el-tag size="small">{{ purposeLabel(identityImportDialog.purpose) }}</el-tag>
        </el-form-item>
        <el-form-item label="国标 ID">
          <el-input v-model="identityImportDialog.gbId" placeholder="关联设备/平台国标编号" />
        </el-form-item>
        <el-form-item label="证书文件">
          <input type="file" ref="identityCertFile" @change="onFileChange('identityCert', $event)" />
        </el-form-item>
        <el-form-item label="私钥文件">
          <input type="file" ref="identityKeyFile" @change="onFileChange('identityKey', $event)" />
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="identityImportDialog.remark" placeholder="可选" />
        </el-form-item>
      </el-form>
      <div class="hint">服务端会校验证书与私钥是否配对；私钥加密存储，不提供下载。</div>
      <div slot="footer">
        <el-button size="mini" @click="identityImportDialog.visible = false">取消</el-button>
        <el-button size="mini" type="primary" :loading="identityImportDialog.loading" @click="submitIdentityImport">导入</el-button>
      </div>
    </el-dialog>

    <!-- ============ 导入对端证书（仅证书） ============ -->
    <el-dialog :title="'导入' + purposeLabel(peerImportDialog.purpose)" :visible.sync="peerImportDialog.visible"
               width="520px" :close-on-click-modal="false">
      <el-form label-width="130px" size="small">
        <el-form-item label="用途">
          <el-tag size="small">{{ purposeLabel(peerImportDialog.purpose) }}</el-tag>
        </el-form-item>
        <el-form-item label="对端国标 ID">
          <el-input v-model="peerImportDialog.gbId" placeholder="上级平台 / 下级设备国标编号" />
        </el-form-item>
        <el-form-item label="证书文件">
          <input type="file" ref="peerCertFile" @change="onFileChange('peerCert', $event)" />
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="peerImportDialog.remark" placeholder="可选" />
        </el-form-item>
      </el-form>
      <div class="hint">对端证书仅保存公钥；即使选择了私钥文件也不会被保存。</div>
      <div slot="footer">
        <el-button size="mini" @click="peerImportDialog.visible = false">取消</el-button>
        <el-button size="mini" type="primary" :loading="peerImportDialog.loading" @click="submitPeerImport">导入</el-button>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import {
  generateCa, importCa, listCa, deleteCa, downloadCa,
  createCsr, signPendingCsr, completePendingCsr, downloadCsr, selfSigned, importIdentity,
  issueFromCsr, reissueFromCsr, importPeer,
  listCert, getCertPolicy, downloadCert, revokeCert, deleteCert, setDefaultCert, reissueServerIdentity,
  PURPOSE_SERVER_IDENTITY, PURPOSE_DEVICE_IDENTITY, PURPOSE_ISSUED_DEVICE, PURPOSE_TRUSTED_PLATFORM,
  PURPOSE_LOCAL_CA, PURPOSE_TRUSTED_CA, PURPOSE_LABELS
} from '@/api/gb35114'
import { getSystemConfig } from '@/api/server'

export default {
  name: 'Gb35114Cert',
  data() {
    return {
      activeTab: 'localCa',
      localGbId: '',
      caList: [],
      caLoading: false,
      certList: [],
      certLoading: false,
      /** 证书策略（只读）：rejectExpiredCert 决定过期证书的提示文案 */
      policy: { rejectExpiredCert: false },
      formRules: {
        gbId: [{ required: true, message: '请输入国标 ID', trigger: 'blur' }],
        subjectCn: [{ required: true, message: '请输入主题 CN', trigger: 'blur' }]
      },
      issueRules: {
        caId: [{ required: true, message: '请选择签发 CA', trigger: 'change' }],
        gbId: [{ required: true, message: '请输入下级国标 ID', trigger: 'blur' }],
        csrPem: [{ required: true, message: '请粘贴 CSR 内容', trigger: 'blur' }]
      },
      caDialog: {
        visible: false, mode: 'generate', title: '生成本地根 CA', purpose: PURPOSE_LOCAL_CA,
        subjectCn: '', remark: '', validityDays: 3650, loading: false
      },
      csrDialog: {
        visible: false, title: '创建证书请求（CSR）', loading: false, purpose: PURPOSE_SERVER_IDENTITY,
        form: this.emptyProfile(PURPOSE_SERVER_IDENTITY)
      },
      issueCsrDialog: {
        visible: false, loading: false,
        form: { caId: null, gbId: '', csrPem: '', remark: '', validityDays: 3650 }
      },
      signDialog: { visible: false, loading: false, id: null, subjectCn: '', caId: null, validityDays: 3650 },
      /** 复用密钥对再签服务端证书：sourceId 提供密钥对，profile 是新证书的档案。 */
      reissueDialog: {
        visible: false, loading: false, sourceId: null, sourceSubjectCn: '',
        caId: null, validityDays: 3650, profile: {}
      },
      selfSignedDialog: {
        visible: false, loading: false, purpose: PURPOSE_SERVER_IDENTITY,
        form: this.emptyProfile(PURPOSE_SERVER_IDENTITY)
      },
      completeDialog: { visible: false, loading: false, id: null, subjectCn: '' },
      identityImportDialog: { visible: false, loading: false, purpose: PURPOSE_SERVER_IDENTITY, gbId: '', remark: '' },
      peerImportDialog: { visible: false, loading: false, purpose: PURPOSE_TRUSTED_PLATFORM, gbId: '', remark: '' },
      files: {
        caCert: null, caKey: null, completeCert: null,
        identityCert: null, identityKey: null, peerCert: null
      }
    }
  },
  computed: {
    localCaList() {
      return this.caList.filter(ca => ca.purpose === PURPOSE_LOCAL_CA)
    },
    serverIdentityList() {
      return this.certList.filter(c => c.purpose === PURPOSE_SERVER_IDENTITY)
    },
    issuedDeviceList() {
      return this.certList.filter(c => c.purpose === PURPOSE_ISSUED_DEVICE)
    },
    deviceIdentityList() {
      return this.certList.filter(c => c.purpose === PURPOSE_DEVICE_IDENTITY)
    },
    trustedPlatformList() {
      return this.certList.filter(c => c.purpose === PURPOSE_TRUSTED_PLATFORM)
    },
    trustedCaList() {
      return this.caList.filter(ca => ca.purpose === PURPOSE_TRUSTED_CA)
    },
    /**
     * 已被证书引用的本地 CA id 集合。
     *
     * <p>本地 CA 现在只允许一份，但存量环境可能有多份。运维需要知道哪一份「在用」——
     * 被引用的那份删不掉（后端 deleteCa 会校验），未被引用的那份才是可清理的。
     */
    usedCaIds() {
      const used = new Set()
      ;(this.certList || []).forEach(c => {
        if (c.caId) used.add(c.caId)
      })
      return used
    }
  },
  mounted() {
    this.loadLocalGbId()
    this.loadPolicy()
    this.loadCaList()
    this.loadCertList()
  },
  methods: {
    /**
     * 距离失效还有多少天（已过期为负数）。无法解析返回 null。
     * 后端存的是 'yyyy-MM-dd HH:mm:ss'，Safari 不认这种格式，需替换成 ISO 的 'T' 分隔。
     */
    daysLeft(row) {
      if (!row || !row.notAfter) return null
      const t = Date.parse(String(row.notAfter).replace(' ', 'T'))
      if (isNaN(t)) return null
      return Math.floor((t - Date.now()) / 86400000)
    },
    /** 过期状态：expired（已过期）/ soon（30 天内到期）/ ok。 */
    expiryState(row) {
      if (!row || row.revoked || !row.certPem) return 'ok'
      const d = this.daysLeft(row)
      if (d === null) return 'ok'
      if (d < 0) return 'expired'
      return d <= 30 ? 'soon' : 'ok'
    },
    /**
     * 剩余有效期文案（如「剩余 12 天」「已过期」）。
     *
     * <p>比较逻辑放在方法里而不是模板里：模板插值中写 {@code <} 会被 Vue 编译器
     * 当成标签起始，报 invalid-first-character-of-tag-name。
     */
    expiryText(row) {
      if (!row || row.revoked || !row.certPem) return ''
      const d = this.daysLeft(row)
      if (d === null) return ''
      return d < 0 ? '已过期' : ('剩余 ' + d + ' 天')
    },
    /**
     * 过期 tag 的提示文案，按后端策略二选一。
     *
     * <p>必须跟着策略走：默认（rejectExpiredCert=false）过期只在页面标出、不拦截注册，
     * 若文案仍写「将被拒绝注册」，运维会误判设备已经被挡在门外而去查网络/设备，
     * 反而把真正该做的事（吊销后重新颁发）漏掉。
     *
     * @param strictText 拒绝过期证书时的文案
     * @param looseText  不拒绝过期证书时的文案
     */
    expiredTip(strictText, looseText) {
      return (this.policy && this.policy.rejectExpiredCert) ? strictText : looseText
    },
    /** 读取证书策略（只读）；失败时按默认策略（不拒绝过期）渲染，不影响列表使用 */
    loadPolicy() {
      getCertPolicy().then(res => {
        const data = (res && res.data) || {}
        this.policy = { rejectExpiredCert: !!data.rejectExpiredCert }
      }).catch(() => {})
    },
    /**
     * 跳到国标设备列表页。
     *
     * <p>设备编辑是列表页内的对话框而非独立路由，无法直接带参打开某一行，
     * 因此这里只做跳转，具体行由运维按「关联设备」列显示的国标 ID 查找。
     */
    goDeviceList() {
      this.$router.push({ path: '/device' })
    },
    /**
     * 本地 CA 唯一性检查。
     *
     * <p>后端已有同样的守卫；提前到打开对话框之前，避免填完表单才被拒。
     *
     * @return true 表示可以继续；false 表示已提示并应中止
     */
    checkLocalCaFree() {
      const exist = this.localCaList[0]
      if (!exist) return true
      const used = this.usedCaIds.has(exist.id)
      this.$confirm(
        '本平台已存在本地 CA #' + exist.id + '（' + (exist.subjectCn || '未命名') + '），'
          + '本地 CA 只保留一份。'
          + (used
            ? '该 CA 正在使用中（已有证书由它签发），删除会被拒绝；如需更换请先处理这些证书。'
            : '该 CA 尚未签发任何证书，可直接删除后再生成或导入新的。'),
        '已有本地 CA',
        { type: 'warning', confirmButtonText: '知道了', showCancelButton: false }
      ).catch(() => {})
      return false
    },
    /** 跳到国标级联列表页（上级平台编辑同样在列表页内的对话框里）。 */
    goPlatformList() {
      this.$router.push({ path: '/platform' })
    },
    /**
     * 服务端密钥对占用检查（仅 SERVER_IDENTITY 需要）。
     *
     * <p>后端已有同样的守卫并会给出明确错误，这里只是把它提前到打开对话框之前 ——
     * 让运维在填完一整个表单后才被拒绝，体验上说不过去。
     *
     * @return true 表示可以继续；false 表示已提示并应中止
     */
    checkServerKeyPairFree(purpose) {
      if (purpose !== PURPOSE_SERVER_IDENTITY) return true
      const active = this.serverIdentityList.find(c => !c.revoked)
      if (!active) return true
      this.$confirm(
        '本平台已有服务端证书 #' + active.id + '（' + (active.subjectCn || '未命名') + '），'
          + '服务端只保留一组密钥对。如需延长有效期或更换主题，请用该行的「同密钥再签」——'
          + '它复用现有密钥对，设备无需重新配置。确需更换密钥时，请先吊销该组全部证书再新建。',
        '已有服务端密钥对',
        { type: 'warning', confirmButtonText: '知道了', showCancelButton: false }
      ).catch(() => {})
      return false
    },
    /** 本平台自身的国标 ID（sip.id），作为本地服务端/客户端证书的默认国标 ID */
    loadLocalGbId() {
      getSystemConfig().then(res => {
        const sip = (res && res.data && res.data.sip) || {}
        this.localGbId = sip.id || ''
      }).catch(() => {})
    },
    emptyProfile(purpose) {
      const isLocal = purpose === PURPOSE_SERVER_IDENTITY || purpose === PURPOSE_DEVICE_IDENTITY
      const gbId = isLocal ? this.localGbId : ''
      return {
        purpose: purpose, gbId: gbId, subjectCn: gbId, country: 'CN', province: '', locality: '',
        organization: '', organizationalUnit: '', remark: '', validityDays: 3650
      }
    },
    purposeLabel(purpose) {
      return PURPOSE_LABELS[purpose] || purpose
    },
    /** 下拉标签带 #id，避免同 CN 证书无法区分 */
    caLabel(ca) {
      return '#' + ca.id + ' ' + (ca.subjectCn || '未命名')
    },
    /** 按 id 取 CA（本地与上级 CA 都在 caList 里） */
    caById(id) {
      if (!id) return null
      return (this.caList || []).find(ca => ca.id === id) || null
    },
    /**
     * 主题列 tooltip：完整 DN 与 CN 不同时才提示。
     *
     * <p>联调环境里 DN 常只有 CN 一段，此时两列内容一模一样 —— 与其并排显示两个相同值的列，
     * 不如把完整 DN 收进 tooltip，既不占列宽也不丢合规审查要看的信息。
     */
    subjectTip(row) {
      const dn = row && row.subjectDn
      if (!dn || dn === row.subjectCn) return ''
      return '完整主题 DN：' + dn
    },
    /**
     * 签发方式文案：显示到「哪个 CA」这一级，而不只是「CA 签发」。
     *
     * <p>多上级场景下，只写「CA 签发」看不出这张证书归属哪个上级；
     * 显示 CA 的 #id 与 CN 才能与「上级 CA」表对上号。
     */
    issuerText(row) {
      if (!row.certPem) return '待签发'
      if (row.caId) {
        const ca = this.caById(row.caId)
        const kind = ca && ca.purpose === PURPOSE_LOCAL_CA ? '本地 CA #' : '上级 CA #'
        return kind + row.caId + (ca ? '（' + (ca.subjectCn || '未命名') + '）' : '（已删除）')
      }
      return row.selfSigned ? '自签' : '签发者未导入'
    },
    /**
     * 签发方式 tag 类型。
     *
     * <p>本地客户端证书必须由上级签发 —— 本地 CA 签的或自签的，上级那边没有签发记录，
     * 接入必然被拒，且失败只出现在上级、本平台日志一切正常。这类一律标红。
     */
    issuerTagType(row) {
      if (!row.certPem) return 'info'
      const ca = row.caId ? this.caById(row.caId) : null
      const locallyIssued = (ca && ca.purpose === PURPOSE_LOCAL_CA) || (!ca && row.selfSigned)
      if (locallyIssued) {
        return row.purpose === PURPOSE_DEVICE_IDENTITY ? 'danger' : 'warning'
      }
      // 有 caId 且是上级 CA 签发 = 正常；caId 为空又非自签 = 签发者未导入
      return ca ? 'success' : 'danger'
    },
    issuerTip(row) {
      if (!row.certPem) {
        return '尚未签发：该记录只有 CSR 与私钥，等待签发后回填证书'
      }
      const ca = row.caId ? this.caById(row.caId) : null
      if (ca) {
        const kind = ca.purpose === PURPOSE_LOCAL_CA ? '本地 CA' : '上级 CA'
        const tail = row.purpose === PURPOSE_DEVICE_IDENTITY && ca.purpose === PURPOSE_LOCAL_CA
          ? '。注意：本平台作客户端时，证书必须由上级签发，本地 CA 签出的证书上级不认'
          : ''
        return '由 ' + kind + ' #' + ca.id + '（' + (ca.subjectCn || '未命名') + '）签发' + tail
      }
      if (row.selfSigned) {
        return '自签：证书由它自己的私钥签署（issuer 与 subject 相同）。'
          + '无 CA 的联调环境可用；正式环境建议改用本地 CA 签发'
      }
      return '签发者未导入：该证书由 ' + (row.issuerDn || '未知 CA') + ' 签发，'
        + '本平台的 CA 列表里没有它。导入对应 CA 后可显示其归属 —— 不影响证书本身的使用。'
    },
    /** 国标 ID 变更时同步 CN（用户仍可手工覆盖） */
    syncCn(value) {
      this.csrDialog.form.subjectCn = value
    },
    syncSelfSignedCn(value) {
      this.selfSignedDialog.form.subjectCn = value
    },

    // ---------------- CA ----------------
    loadCaList() {
      this.caLoading = true
      listCa().then(res => {
        this.caList = (res && res.data) || []
      }).finally(() => { this.caLoading = false })
    },
    openCaGenerate() {
      if (!this.checkLocalCaFree()) return
      this.caDialog = {
        visible: true, mode: 'generate', title: '生成本地根 CA', purpose: PURPOSE_LOCAL_CA,
        name: '', subjectCn: '', remark: '', validityDays: 3650, loading: false
      }
    },
    /** purpose: LOCAL_CA（需私钥，用于签发）/ TRUSTED_CA（仅公钥，验链） */
    openCaImport(purpose) {
      const p = purpose || PURPOSE_LOCAL_CA
      if (p === PURPOSE_LOCAL_CA && !this.checkLocalCaFree()) return
      this.caDialog = {
        visible: true, mode: 'import',
        title: p === PURPOSE_LOCAL_CA ? '导入本地 CA' : '导入上级 CA',
        purpose: p,
        name: '', subjectCn: '', remark: '', validityDays: 3650, loading: false
      }
      this.files.caCert = null
      this.files.caKey = null
      if (this.$refs.caCertFile) this.$refs.caCertFile.value = ''
      if (this.$refs.caKeyFile) this.$refs.caKeyFile.value = ''
    },
    submitCa() {
      this.caDialog.loading = true
      if (this.caDialog.mode === 'generate') {
        if (!this.caDialog.subjectCn) {
          this.caDialog.loading = false
          this.$message.warning('请输入主题 CN')
          return
        }
        generateCa({
          subjectCn: this.caDialog.subjectCn,
          remark: this.caDialog.remark
        })
          .then(() => { this.caDialog.visible = false; this.$message.success('生成成功'); this.loadCaList() })
          .finally(() => { this.caDialog.loading = false })
      } else {
        if (!this.files.caCert) {
          this.caDialog.loading = false
          this.$message.warning('请选择 CA 证书文件')
          return
        }
        importCa({
          purpose: this.caDialog.purpose,
          remark: this.caDialog.remark,
          certFile: this.files.caCert,
          keyFile: this.files.caKey
        })
          .then(() => { this.caDialog.visible = false; this.$message.success('导入成功'); this.loadCaList() })
          .finally(() => { this.caDialog.loading = false })
      }
    },
    confirmDeleteCa(row) {
      this.$confirm('确认删除该 CA？若其下仍有证书将拒绝删除。', '提示', { type: 'warning' }).then(() => {
        deleteCa(row.id).then(() => { this.$message.success('删除成功'); this.loadCaList() })
      }).catch(() => {})
    },

    // ---------------- 证书列表 ----------------
    refreshAll() {
      this.loadCaList()
      this.loadCertList()
    },
    loadCertList() {
      this.certLoading = true
      listCert().then(res => {
        this.certList = (res && res.data) || []
      }).finally(() => { this.certLoading = false })
    },

    // ---------------- 创建 CSR ----------------
    openIdentity(purpose) {
      if (!this.checkServerKeyPairFree(purpose)) return
      this.csrDialog = {
        visible: true, title: '创建证书请求（CSR）- ' + this.purposeLabel(purpose),
        loading: false, purpose: purpose, form: this.emptyProfile(purpose)
      }
      this.$nextTick(() => { if (this.$refs.csrForm) this.$refs.csrForm.clearValidate() })
    },
    submitCsr() {
      this.$refs.csrForm.validate(valid => {
        if (!valid) return
        const f = this.csrDialog.form
        this.csrDialog.loading = true
        createCsr({
          purpose: this.csrDialog.purpose,
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
            this.csrDialog.visible = false
            this.$message.success('CSR 已生成，可在列表中导出并提交给 CA')
            this.loadCertList()
            return res
          })
          .finally(() => { this.csrDialog.loading = false })
      })
    },

    // ---------------- 由下级 CSR 签发 ----------------
    openIssueFromCsr() {
      this.issueCsrDialog = {
        visible: true, loading: false,
        form: {
          caId: this.localCaList.length ? this.localCaList[0].id : null,
          gbId: '', csrPem: '', remark: '', validityDays: 3650
        }
      }
      this.$nextTick(() => { if (this.$refs.issueCsrForm) this.$refs.issueCsrForm.clearValidate() })
    },
    submitIssueFromCsr() {
      this.$refs.issueCsrForm.validate(valid => {
        if (!valid) return
        const f = this.issueCsrDialog.form
        this.issueCsrDialog.loading = true
        issueFromCsr({
          caId: f.caId, gbId: f.gbId, csrPem: f.csrPem, remark: f.remark,
          validityDays: f.validityDays
        })
          .then(() => {
            this.issueCsrDialog.visible = false
            this.$message.success('签发成功，请导出证书交付下级')
            this.loadCertList()
          })
          .finally(() => { this.issueCsrDialog.loading = false })
      })
    },

    // ---------------- 待签发记录：本地签发 / 回填 ----------------
    openSignPending(row) {
      this.signDialog = {
        visible: true, loading: false, id: row.id, subjectCn: row.subjectCn,
        caId: this.localCaList.length ? this.localCaList[0].id : null, validityDays: row.validityDays || 3650
      }
    },
    submitSignPending() {
      if (!this.signDialog.caId) {
        this.$message.warning('请选择本地 CA')
        return
      }
      this.signDialog.loading = true
      signPendingCsr(this.signDialog.id, this.signDialog.caId, this.signDialog.validityDays)
        .then(() => { this.signDialog.visible = false; this.$message.success('签发成功'); this.loadCertList() })
        .finally(() => { this.signDialog.loading = false })
    },
    openCompletePending(row) {
      this.completeDialog = { visible: true, loading: false, id: row.id, subjectCn: row.subjectCn }
      this.files.completeCert = null
      if (this.$refs.completeCertFile) this.$refs.completeCertFile.value = ''
    },
    submitCompletePending() {
      if (!this.files.completeCert) {
        this.$message.warning('请选择证书文件')
        return
      }
      this.completeDialog.loading = true
      completePendingCsr(this.completeDialog.id, this.files.completeCert)
        .then(() => { this.completeDialog.visible = false; this.$message.success('回填成功'); this.loadCertList() })
        .finally(() => { this.completeDialog.loading = false })
    },

    // ---------------- 自签 / 导入 ----------------
    openSelfSigned(purpose) {
      if (!this.checkServerKeyPairFree(purpose)) return
      this.selfSignedDialog = {
        visible: true, loading: false, purpose: purpose,
        form: this.emptyProfile(purpose)
      }
      this.$nextTick(() => { if (this.$refs.selfSignedForm) this.$refs.selfSignedForm.clearValidate() })
    },
    submitSelfSigned() {
      this.$refs.selfSignedForm.validate(valid => {
        if (!valid) return
        const f = this.selfSignedDialog.form
        this.selfSignedDialog.loading = true
        selfSigned({
          purpose: this.selfSignedDialog.purpose,
          gbId: f.gbId,
          subjectCn: f.subjectCn || f.gbId,
          country: f.country,
          province: f.province,
          locality: f.locality,
          organization: f.organization,
          organizationalUnit: f.organizationalUnit,
          remark: f.remark
        }, f.validityDays)
          .then(() => { this.selfSignedDialog.visible = false; this.$message.success('生成成功'); this.loadCertList() })
          .finally(() => { this.selfSignedDialog.loading = false })
      })
    },
    openIdentityImport(purpose) {
      if (!this.checkServerKeyPairFree(purpose)) return
      this.identityImportDialog = { visible: true, loading: false, purpose: purpose, gbId: '', remark: '' }
      this.files.identityCert = null
      this.files.identityKey = null
      if (this.$refs.identityCertFile) this.$refs.identityCertFile.value = ''
      if (this.$refs.identityKeyFile) this.$refs.identityKeyFile.value = ''
    },
    submitIdentityImport() {
      if (!this.files.identityCert || !this.files.identityKey) {
        this.$message.warning('请选择证书与私钥文件')
        return
      }
      this.identityImportDialog.loading = true
      importIdentity({
        purpose: this.identityImportDialog.purpose,
        gbId: this.identityImportDialog.gbId,
        remark: this.identityImportDialog.remark
      }, this.files.identityCert, this.files.identityKey)
        .then(() => { this.identityImportDialog.visible = false; this.$message.success('导入成功'); this.loadCertList() })
        .finally(() => { this.identityImportDialog.loading = false })
    },
    openPeerImport(purpose) {
      this.peerImportDialog = { visible: true, loading: false, purpose: purpose, gbId: '', remark: '' }
      this.files.peerCert = null
      if (this.$refs.peerCertFile) this.$refs.peerCertFile.value = ''
    },
    submitPeerImport() {
      if (!this.files.peerCert) {
        this.$message.warning('请选择证书文件')
        return
      }
      this.peerImportDialog.loading = true
      importPeer({
        purpose: this.peerImportDialog.purpose,
        gbId: this.peerImportDialog.gbId,
        remark: this.peerImportDialog.remark
      }, this.files.peerCert)
        .then(() => { this.peerImportDialog.visible = false; this.$message.success('导入成功'); this.loadCertList() })
        .finally(() => { this.peerImportDialog.loading = false })
    },

    // ---------------- 生命周期 ----------------
    confirmRevoke(row) {
      this.$confirm('确认吊销该证书？', '提示', { type: 'warning' }).then(() => {
        revokeCert(row.id).then(() => { this.$message.success('已吊销'); this.loadCertList() })
      }).catch(() => {})
    },
    confirmDeleteCert(row) {
      this.$confirm('确认删除该证书？本地身份证书的私钥将一并删除，且不可恢复。', '提示', { type: 'warning' })
        .then(() => {
          deleteCert(row.id).then(() => { this.$message.success('删除成功'); this.loadCertList() })
        }).catch(() => {})
    },
    confirmSetDefault(row) {
      this.$confirm(
        `确认把「${row.subjectCn || row.gbId}」设为默认服务端证书？未绑定设备的设备将用它签 sign2。` +
        '若某台设备只信任另一张证书，请改为在该设备上绑定，不要改默认证书。',
        '提示', { type: 'warning' }
      ).then(() => {
        setDefaultCert(row.id).then(() => { this.$message.success('已设为默认'); this.loadCertList() })
      }).catch(() => {})
    },
    /** 复用源证书的密钥对再签一张（公钥不变，设备无需重新配置）。 */
    openReissue(row) {
      this.reissueDialog = {
        visible: true,
        loading: false,
        sourceId: row.id,
        sourceSubjectCn: row.subjectCn,
        caId: row.caId || null,
        validityDays: row.validityDays || 3650,
        // 默认沿用源证书的档案，用户可改
        profile: {
          purpose: PURPOSE_SERVER_IDENTITY,
          subjectCn: row.subjectCn,
          gbId: row.gbId,
          country: row.country,
          province: row.province,
          locality: row.locality,
          organization: row.organization,
          organizationalUnit: row.organizationalUnit,
          remark: row.remark
        }
      }
    },
    submitReissue() {
      this.reissueDialog.loading = true
      reissueServerIdentity(
        this.reissueDialog.sourceId,
        this.reissueDialog.profile,
        this.reissueDialog.caId,
        this.reissueDialog.validityDays
      ).then(() => {
        this.reissueDialog.visible = false
        this.$message.success('已用同一密钥对签发新证书，设备无需重新配置')
        this.loadCertList()
      }).finally(() => { this.reissueDialog.loading = false })
    },

    // ---------------- 下载 ----------------
    /** kind: 'cert' 证书 | 'csr' 证书请求。私钥无下载入口。 */
    downloadFile(kind, row) {
      const fn = kind === 'csr' ? downloadCsr : downloadCert
      const ext = kind === 'csr' ? '.csr' : '.crt'
      fn(row.id).then(res => {
        const blob = new Blob([res])
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = (row.gbId || row.subjectCn || 'cert') + ext
        a.click()
        window.URL.revokeObjectURL(url)
      }).catch(() => {
        this.$message.warning(kind === 'csr' ? '该记录无 CSR 可导出' : '下载失败')
      })
    },
    /** 导出 CA 证书（交付摄像头/对端导入，用于验签本平台签发的证书） */
    downloadCaFile(ca) {
      downloadCa(ca.id).then(res => {
        const blob = new Blob([res])
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = (ca.subjectCn || 'ca') + '.crt'
        a.click()
        window.URL.revokeObjectURL(url)
      }).catch(() => { this.$message.warning('导出 CA 证书失败') })
    },
    onCsrFileChange(e) {
      const file = e.target.files[0]
      if (!file) return
      const reader = new FileReader()
      reader.onload = () => {
        this.issueCsrDialog.form.csrPem = String(reader.result || '').trim()
        this.fillGbIdFromCsr()
        this.$nextTick(() => { if (this.$refs.issueCsrForm) this.$refs.issueCsrForm.clearValidate('csrPem') })
      }
      reader.onerror = () => this.$message.warning('读取 CSR 文件失败')
      reader.readAsText(file)
      // 允许重复选择同一文件
      e.target.value = ''
    },
    /** 下级国标 ID 留空时，从 CSR 主题 CN 提取（CN 通常即国标编码） */
    fillGbIdFromCsr() {
      const f = this.issueCsrDialog.form
      if (f.gbId) return
      const pem = (f.csrPem || '').trim()
      if (!pem) return
      // 取第一行 CN=...（RFC2253，反斜杠转义不处理）
      const m = pem.match(/CN\s*=\s*([^,\n]+)/)
      if (m && m[1]) {
        f.gbId = m[1].trim()
      }
    },
    onFileChange(field, e) {
      this.files[field] = e.target.files[0] || null
    }
  }
}
</script>

<style scoped>
.toolbar {
  margin-bottom: 8px;
}
.tip {
  margin-bottom: 12px;
}
.hint {
  font-size: 12px;
  color: #909399;
  margin: 8px 0 12px;
  line-height: 1.6;
}
.hint-inline {
  font-size: 12px;
  color: #909399;
  margin-left: 8px;
}
/* 主题列：过长时省略号截断，完整 DN 走 tooltip */
.cell-ellipsis {
  display: inline-block;
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  vertical-align: middle;
}
</style>
