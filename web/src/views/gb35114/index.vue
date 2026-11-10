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
        : '当前策略：不拒绝已过期的证书（gb35114.reject-expired-cert=false）—— 过期仅在下方标出，不影响接入；请看到「已过期」后及时删除并重新颁发。'"
    />

    <!--
      校验是默认行为，不提示（提示了反而天天占着版面）；这里只标出「被关掉」这个偏离默认的状态。
      与下面 skipCertChainVerify 的红色告警同一思路：默认值不吭声，放宽了才说。
    -->
    <el-alert
      v-if="!policy.verifyUpstreamCertChain"
      type="warning"
      :closable="false"
      show-icon
      class="tip"
      title="当前策略：不校验上级证书链（gb35114.verify-upstream-cert-chain=false）—— 上级证书无需由已导入的「受信任的 CA」签发即可注册。这是放宽项：无法防住用任意证书冒充上级。需要从严就把该项改回 true 并重启；上级证书是自签的，把该证书本身在「CA 证书管理」里也作为「受信任的 CA」导入一份即可通过校验。"
    />

    <el-alert
      v-if="policy.skipCertChainVerify"
      type="error"
      :closable="false"
      show-icon
      class="tip"
      title="当前策略：已跳过证书链验证（gb35114.skip-cert-chain-verify=true）—— 不再要求证书由已导入的 CA 签发，用于现场拿不到 CA 的情况。指纹反查、有效期与握手验签仍然生效，但无法再防住「证书被替换」。拿到 CA 后请尽快改回 false 并重启。"
    />

    <el-tabs v-model="activeTab" type="card">
      <!-- ==================== 1. CA 证书管理（两栏：本地根 CA / 受信任的 CA） ==================== -->
      <el-tab-pane label="CA 证书管理" name="localCa">
        <div class="hint">
          CA 按<b>是否持有私钥</b>分两栏：本地根 CA 持私钥、可签发；受信任的 CA 只有公钥、
          不能签发，只参与证书链校验。两栏与「服务哪个方向」无关 —— 受信任的 CA 既能验证
          上级平台证书，也能验证第三方机构签发给下级设备的证书。
        </div>

        <!-- ---- 1.1 本地根 CA 证书（本平台生成） ---- -->
        <div class="section-title">本地根 CA 证书（本平台生成）</div>
        <el-form :inline="true" size="mini" class="toolbar">
          <el-form-item>
            <el-button type="primary" icon="el-icon-plus" size="mini" @click="openCaGenerate">生成本地根 CA</el-button>
            <el-button icon="el-icon-refresh-right" size="mini" circle @click="loadCaList" />
          </el-form-item>
        </el-form>
        <div class="hint">
          私钥留在本平台，用于签发本平台的服务端证书与客户端证书，以及下级设备的客户端证书。<br>
          <b>本平台生成的 CA 不出平台</b>：这里只提供「生成」一个入口，不提供导入 ——
          私钥不允许导出，也就不存在把它搬回来这一回事。<br>
          <b>本地根 CA 只保留一份</b>：已存在时「生成本地根 CA」会被拒绝，需先删除旧的
          （仍被证书引用的删不掉）。<br>
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
          <el-table-column label="关联证书" width="100">
            <template v-slot:default="scope">
              <el-button type="text" size="mini" :disabled="!scope.row.certCount"
                         @click="openCaCerts(scope.row)">
                {{ scope.row.certCount === null || scope.row.certCount === undefined
                  ? '统计失败' : scope.row.certCount + ' 张' }}
              </el-button>
            </template>
          </el-table-column>
          <el-table-column prop="remark" label="备注" min-width="160" show-overflow-tooltip />
          <el-table-column label="操作" width="140" fixed="right">
            <template v-slot:default="scope">
              <el-button type="text" size="mini" @click="downloadCaFile(scope.row)">导出</el-button>
              <el-button type="text" size="mini" style="color: #f56c6c" @click="confirmDeleteCa(scope.row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>

        <!-- ---- 1.2 受信任的 CA 证书（需导入） ---- -->
        <div class="section-title" style="margin-top: 20px">受信任的 CA 证书（外部签发，需导入）</div>
        <el-form :inline="true" size="mini" class="toolbar">
          <el-form-item>
            <el-button type="warning" icon="el-icon-upload2" size="mini" @click="openCaImport('TRUSTED_CA')">导入受信任的 CA</el-button>
            <el-button icon="el-icon-refresh-right" size="mini" circle @click="loadCaList" />
          </el-form-item>
        </el-form>
        <div class="hint">
          由外部机构签发的 CA 证书，<b>只保存公钥</b>，不可用于签发。它参与两类证书链校验：<br>
          ① <b>上级平台的服务端证书</b> —— 默认校验「上级证书链」，上级证书必须能由本栏某个 CA 签发；
          自签的上级证书要把该证书本身也导入本栏一份。不校验就置
          <code>gb35114.verify-upstream-cert-chain=false</code>；<br>
          ② <b>下级设备的客户端证书</b> —— 第三方机构签发给设备的证书，导入后由本栏的 CA 完成链校验。<br>
          校验是<b>实时</b>的：每次设备/上级注册都重新读取本栏并验签，没有「导入时标记为可信」这回事。
          因此删除本栏某个 CA 会立刻影响后续接入；仍被证书引用的 CA 后端会拒绝删除。
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
          <el-table-column label="关联证书" width="100">
            <template v-slot:default="scope">
              <el-button type="text" size="mini" :disabled="!scope.row.certCount"
                         @click="openCaCerts(scope.row)">
                {{ scope.row.certCount === null || scope.row.certCount === undefined
                  ? '统计失败' : scope.row.certCount + ' 张' }}
              </el-button>
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
                          content="本平台导入的上级平台服务端证书里，没有一张由本 CA 签发 —— 可能是证书还没导入，或该 CA 只用于验证下级设备证书"
                          placement="top">
                <span style="color: #c0c4cc">未关联</span>
              </el-tooltip>
            </template>
          </el-table-column>
          <el-table-column prop="notAfter" label="失效时间" min-width="170" />
          <el-table-column prop="remark" label="备注" min-width="140" show-overflow-tooltip />
          <el-table-column label="操作" width="120" fixed="right">
            <template v-slot:default="scope">
              <el-button type="text" size="mini" @click="downloadCaFile(scope.row)">导出</el-button>
              <el-button type="text" size="mini" style="color: #f56c6c" @click="confirmDeleteCa(scope.row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <!-- ==================== 2. 下级接入 · 服务端证书（本平台） ==================== -->
      <el-tab-pane label="下级接入 · 服务端证书（本平台）" name="serverIdentity">
        <el-form :inline="true" size="mini" class="toolbar">
          <el-form-item>
            <el-button type="primary" icon="el-icon-plus" size="mini" @click="openServerIdentity">创建服务端证书</el-button>
            <el-button icon="el-icon-document-add" size="mini" @click="openIdentity('SERVER_IDENTITY')">创建 CSR</el-button>
            <el-button icon="el-icon-upload2" size="mini" @click="openIdentityImport('SERVER_IDENTITY')">导入（证书+私钥）</el-button>
            <el-button icon="el-icon-refresh-right" size="mini" circle @click="loadCertList" />
          </el-form-item>
        </el-form>
        <div class="hint">
          本平台作 UAS，对 sign2 签名。私钥留在本平台，不可下载。三条路产出的都是同一件事，
          按现场条件选一条：<br>
          <b>① 创建服务端证书</b> —— 密钥对与签发一次完成，最省事；<br>
          <b>② 创建 CSR</b> —— 先出 CSR，再由本平台用本地根 CA 签发（也可自签）；
          需要留存 CSR、或签发动作要另行审批时用它；<br>
          <b>③ 导入（证书+私钥）</b> —— 证书由外部机构签发，把证书与配对私钥一起导入。<br>
          <b>平台只保留一组服务端密钥对</b>：已存在服务端证书时，上述三个入口都会被拒绝 ——
          多组密钥并存时，设备绑定的是哪一组无从判断，选错会让设备验 sign2 失败而平台日志一切正常。<br>
          <b>更换（含延长有效期、换主题）请先删除、再重新创建。</b>
          新证书是<b>新的密钥对</b>，设备侧存的还是旧公钥，因此绑定过它的设备与级联平台需要
          <b>重新导入本平台证书</b>才能继续注册。
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
                            '已过期：该证书不能用于签 sign2，绑定它的设备将被拒绝注册',
                            '已过期：当前策略不拒绝过期证书，仍可用于签 sign2；建议删除后重新创建')"
                          placement="top">
                <el-tag size="mini" type="danger">已过期</el-tag>
              </el-tooltip>
              <el-tooltip v-else-if="expiryState(scope.row) === 'soon'"
                          :content="'即将过期（剩余 ' + daysLeft(scope.row) + ' 天），请提前删除后重新创建'"
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
                          :content="'公钥指纹 ' + scope.row.keyFingerprint + '（设备侧导入的就是这把公钥）'">
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
          <el-table-column label="操作" width="240" fixed="right">
            <template v-slot:default="scope">
              <!-- 待签发（走「创建 CSR」的那条路）：CSR 下载 / 用本地根 CA 签发 / 回填外部证书 -->
              <template v-if="!scope.row.certPem">
                <el-button type="text" size="mini" @click="downloadFile('csr', scope.row)">CSR</el-button>
                <el-button type="text" size="mini" style="color: #e6a23c" @click="openSignPending(scope.row)">签发</el-button>
                <el-button type="text" size="mini" @click="openCompletePending(scope.row)">回填</el-button>
              </template>
              <template v-else>
                <el-button type="text" size="mini" @click="downloadFile('cert', scope.row)">证书</el-button>
              </template>
              <el-button type="text" size="mini" style="color: #f56c6c" @click="confirmDeleteCert(scope.row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <!-- ==================== 3. 下级接入 · 客户端证书（下级设备） ==================== -->
      <el-tab-pane label="下级接入 · 客户端证书（下级设备）" name="issuedDevice">
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
          一律拒绝接入 —— 设备自签的证书平台没有记录，既无从判断有效性，出事时也无从追溯。
          <b>第三方机构签发的证书同样要先导入</b>（「导入下级证书」），
          并把签发它的 CA 导入 <b>CA 证书管理 · 受信任的 CA 证书</b>，
          否则链校验不通过、设备仍会被拒。<br />
          <b>删除即刻生效</b>：设备自报的证书按公钥指纹反查本表，记录不存在即拒绝接入。
        </div>

        <el-table :data="issuedDeviceList" v-loading="certLoading" size="small" border style="width: 100%">
          <el-table-column prop="id" label="ID" width="60" />
          <el-table-column prop="gbId" label="下级客户端编码" min-width="180">
            <template v-slot:default="scope">{{ scope.row.gbId || '-' }}</template>
          </el-table-column>
          <el-table-column label="关联设备" min-width="180" show-overflow-tooltip>
            <template v-slot:default="scope">
              <el-tooltip v-if="scope.row.relatedDeviceName"
                          :content="'本平台为该设备签发的客户端证书：' + scope.row.relatedDeviceName
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
          <el-table-column label="密码模块 ID" min-width="180">
            <template v-slot:default="scope">
              <el-tooltip :content="moduleIdTip(scope.row)" placement="top">
                <span class="cell-ellipsis">{{ scope.row.moduleId || '-' }}</span>
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
              <el-button type="text" size="mini" style="color: #f56c6c" @click="confirmDeleteCert(scope.row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <!-- ==================== 4. 上级接入 · 客户端证书（本平台） ==================== -->
      <el-tab-pane label="上级接入 · 客户端证书（本平台）" name="deviceIdentity">
        <el-form :inline="true" size="mini" class="toolbar">
          <el-form-item>
            <el-button icon="el-icon-refresh-right" size="mini" circle @click="loadCertList" />
          </el-form-item>
        </el-form>
        <div class="hint">
          本平台作 UAC（含国标级联作下级接入上级），对 sign1 签名。<b>这张证书必须由上级签发</b>：
          本平台作客户端，上级作服务端，只有上级自己签发并留存的证书它才认。<br />
          新建入口在 <b>国标级联 → 编辑上级平台</b> 的「国密设备证书」槽（<b>创建 CSR</b> →
          导出交上级签发 → 回到那里点<b>回填</b>）。本页保留列表与行内的
          <b>CSR</b> / <b>回填</b> / <b>证书</b> / <b>删除</b>，跨天的回填流程在这里收尾。<br />
          私钥留在本平台，不可下载。此处<b>不提供一步创建</b>：本平台自签或用本地 CA 签出来的证书，
          上级那边没有签发记录，接入必然被拒 —— 而失败只出现在上级，本平台日志一切正常，排查容易跑偏。<br />
          接入多个上级时，每个上级各签一张本平台的客户端证书，并在
          <b>国标级联 → 编辑上级平台</b> 的「国密设备证书」槽里绑定；「关联平台」列即显示该绑定关系。
        </div>

        <el-table :data="deviceIdentityList" v-loading="certLoading" size="small" border style="width: 100%">
          <el-table-column prop="id" label="ID" width="60" />
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
                          content="没有级联平台显式绑定本证书。本用途只有这一张时按上级国标编码匹配兜底；有多张则拒绝猜测，需在级联编辑页逐条绑定"
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
              <el-button type="text" size="mini" style="color: #f56c6c" @click="confirmDeleteCert(scope.row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <!-- ==================== 5. 上级接入 · 服务端证书（上级平台） ==================== -->
      <el-tab-pane label="上级接入 · 服务端证书（上级平台）" name="trustedPlatform">
        <el-form :inline="true" size="mini" class="toolbar">
          <el-form-item>
            <el-button icon="el-icon-refresh-right" size="mini" circle @click="loadCertList" />
          </el-form-item>
        </el-form>
        <div class="hint">
          上级平台的服务端证书，仅含公钥，用于对上级下发的 sign2 验签。本平台不持有其私钥。<br />
          导入入口在 <b>国标级联 → 编辑上级平台</b> 的「上级平台证书」槽；本页保留列表与行内的
          <b>证书</b> / <b>删除</b>。<br />
          接入多个上级时，每个上级各导入一张，并在 <b>国标级联 → 编辑上级平台</b> 的
          「上级平台证书」槽里绑定；「关联平台」列即显示该绑定关系。<br />
          默认要校验「上级证书链」，这些证书还要能由某个 CA 签发 —— 请到
          <b>CA 证书管理 → 受信任的 CA 证书</b> 导入签发它们的 CA（自签的上级证书把它本身导入一份即可）。
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
                          content="没有级联平台显式绑定本证书。本用途只有这一张时按上级国标编码匹配兜底；有多张则拒绝猜测，需在级联编辑页逐条绑定"
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
              <el-button type="text" size="mini" style="color: #f56c6c" @click="confirmDeleteCert(scope.row)">删除</el-button>
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
            <el-input v-model="caDialog.subjectCn" placeholder="国标ID_密码模块ID" />
            <span class="hint-inline">默认「本平台国标 ID_密码模块 ID」，与其它证书主题同一格式，可直接改</span>
          </el-form-item>
          <el-row>
            <el-col :span="12">
              <el-form-item label="国家（C）">
                <el-input v-model="caDialog.country" placeholder="CN" />
              </el-form-item>
            </el-col>
            <el-col :span="12">
              <el-form-item label="省份（ST）">
                <el-input v-model="caDialog.province" />
              </el-form-item>
            </el-col>
          </el-row>
          <el-row>
            <el-col :span="12">
              <el-form-item label="城市（L）">
                <el-input v-model="caDialog.locality" />
              </el-form-item>
            </el-col>
            <el-col :span="12">
              <el-form-item label="组织（O）">
                <el-input v-model="caDialog.organization" />
              </el-form-item>
            </el-col>
          </el-row>
          <el-form-item label="组织单位（OU）">
            <el-input v-model="caDialog.organizationalUnit" />
          </el-form-item>
          <el-form-item label="有效期（天）">
            <el-input-number v-model="caDialog.validityDays" :min="1" :max="36500" controls-position="right" />
            <span class="hint-inline">自签发时刻起算</span>
          </el-form-item>
          <el-form-item label="备注">
            <el-input v-model="caDialog.remark" placeholder="可选" />
          </el-form-item>
        </template>
        <template v-else>
          <el-form-item label="CA 用途">
            <el-tag size="small">受信任的 CA（仅公钥，参与证书链校验）</el-tag>
          </el-form-item>
          <el-form-item label="证书文件（.crt/.pem）">
            <input type="file" ref="caCertFile" @change="onFileChange('caCert', $event)" />
          </el-form-item>
          <el-form-item label="备注">
            <el-input v-model="caDialog.remark" placeholder="可选" />
          </el-form-item>
          <div class="hint">受信任的 CA 仅保存公钥，用于校验上级平台证书与第三方签发给下级设备的证书，不可用于签发。</div>
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
        <el-form-item label="主题（CN）" prop="subjectCn">
          <el-input v-model="csrDialog.form.subjectCn" placeholder="国标ID_密码模块ID"
                    @input="syncGbIdFromCn" />
          <span class="hint-inline">默认「本平台国标 ID_密码模块 ID」已按附录 A 表 A.1 生成；
            接入上级时若本平台编码不适用（避免冲突），可直接改这里</span>
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

    <!-- ============ 创建服务端证书（一步：生成密钥对 + 当场签发） ============ -->
    <el-dialog title="创建服务端证书（本平台）" :visible.sync="serverIdentityDialog.visible"
               width="620px" :close-on-click-modal="false">
      <el-form ref="serverIdentityForm" :model="serverIdentityDialog.form" :rules="formRules" label-width="130px" size="small">
        <el-form-item label="签发方式">
          <el-select v-model="serverIdentityDialog.caId" clearable placeholder="自签（不选 CA）" style="width: 100%">
            <el-option v-for="ca in localCaList" :key="ca.id" :label="caLabel(ca)" :value="ca.id" />
          </el-select>
          <span class="hint-inline">选本地 CA 则由它签发；不选则自签</span>
        </el-form-item>
        <el-form-item label="主题（CN）" prop="subjectCn">
          <el-input v-model="serverIdentityDialog.form.subjectCn" placeholder="国标ID_密码模块ID"
                    @input="syncServerIdentityGbIdFromCn" />
          <span class="hint-inline">默认「本平台国标 ID_密码模块 ID」已按附录 A 表 A.1 生成，可直接改</span>
        </el-form-item>
        <el-row>
          <el-col :span="12">
            <el-form-item label="国家（C）">
              <el-input v-model="serverIdentityDialog.form.country" placeholder="CN" />
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item label="省份（ST）">
              <el-input v-model="serverIdentityDialog.form.province" />
            </el-form-item>
          </el-col>
        </el-row>
        <el-row>
          <el-col :span="12">
            <el-form-item label="城市（L）">
              <el-input v-model="serverIdentityDialog.form.locality" />
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item label="组织（O）">
              <el-input v-model="serverIdentityDialog.form.organization" />
            </el-form-item>
          </el-col>
        </el-row>
        <el-form-item label="组织单位（OU）">
          <el-input v-model="serverIdentityDialog.form.organizationalUnit" />
        </el-form-item>
        <el-form-item label="有效期（天）">
          <el-input-number v-model="serverIdentityDialog.form.validityDays" :min="1" :max="36500" controls-position="right" />
          <span class="hint-inline">自签发时刻起算</span>
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="serverIdentityDialog.form.remark" placeholder="可选" />
        </el-form-item>
      </el-form>
      <div class="hint">
        密钥对在本平台生成，私钥加密留存、不可下载。<br />
        用本地 CA 签发时，设备侧只需导入一次<b>CA 证书</b>即可验证本平台签发的证书；
        自签则设备侧要导入<b>本平台证书本身</b>。无 CA 的联调环境可用自签。
      </div>
      <div slot="footer">
        <el-button size="mini" @click="serverIdentityDialog.visible = false">取消</el-button>
        <el-button size="mini" type="primary" :loading="serverIdentityDialog.loading" @click="submitServerIdentity">创建</el-button>
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
      <div class="hint">下级提交的是 <b>CSR（证书请求）</b>，只含下级公钥、不含私钥；本平台用本地根 CA 对其签发，产出证书交付下级。<br>
        若对端证书已由别的 CA（含第三方机构）签发，请改用列表上方的「导入下级证书（.crt）」——
        导入后还需把签发它的 CA 导入「CA 证书管理 · 受信任的 CA 证书」，设备注册时才能通过链校验。</div>
      <div slot="footer">
        <el-button size="mini" @click="issueCsrDialog.visible = false">取消</el-button>
        <el-button size="mini" type="primary" :loading="issueCsrDialog.loading" @click="submitIssueFromCsr">签发</el-button>
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
      <div class="hint">把外部签发好的证书回填到这条待签发记录。服务端会校验证书公钥与本地留存私钥是否配对，
        不配对则拒绝 —— 配对是硬要求：不配对时设备侧验 sign2/sign1 必然失败，而本平台日志一切正常。<br>
        服务端证书若由本平台自己签发，请改用列表上的<b>签发</b>按钮（不必来回导文件）。</div>
      <div slot="footer">
        <el-button size="mini" @click="completeDialog.visible = false">取消</el-button>
        <el-button size="mini" type="primary" :loading="completeDialog.loading" @click="submitCompletePending">确定</el-button>
      </div>
    </el-dialog>

    <!-- ============ 用本地根 CA 签发待签发的服务端证书 ============ -->
    <el-dialog title="用本地根 CA 签发服务端证书" :visible.sync="signPendingDialog.visible"
               width="520px" :close-on-click-modal="false">
      <el-form label-width="130px" size="small">
        <el-form-item label="待签发记录">
          <span>{{ signPendingDialog.subjectCn }}（#{{ signPendingDialog.id }}）</span>
        </el-form-item>
        <el-form-item label="签发 CA">
          <el-select v-model="signPendingDialog.caId" clearable placeholder="自签（不选 CA）" style="width: 100%">
            <el-option v-for="ca in localCaList" :key="ca.id" :label="caLabel(ca)" :value="ca.id" />
          </el-select>
          <span class="hint-inline">选本地根 CA 则由它签发；不选则自签</span>
        </el-form-item>
        <el-form-item label="有效期（天）">
          <el-input-number v-model="signPendingDialog.validityDays" :min="1" :max="36500" controls-position="right" />
          <span class="hint-inline">自签发时刻起算</span>
        </el-form-item>
      </el-form>
      <div class="hint">
        就地更新这条记录（复用其私钥），<b>不新建记录</b>：设备与级联平台绑定的是记录 ID，新建会让引用悬空。<br>
        用本地根 CA 签发时，设备侧只需导入一次 <b>CA 证书</b>即可验证本平台签发的证书；
        自签则设备侧要导入<b>本平台证书本身</b>。无 CA 的联调环境可用自签。
      </div>
      <div slot="footer">
        <el-button size="mini" @click="signPendingDialog.visible = false">取消</el-button>
        <el-button size="mini" type="primary" :loading="signPendingDialog.loading" @click="submitSignPending">签发</el-button>
      </div>
    </el-dialog>

    <!-- ============ CA 关联证书清单 ============ -->
    <el-drawer :title="caCertsDrawer.title" :visible.sync="caCertsDrawer.visible" size="60%" append-to-body>
      <div style="padding: 0 20px 20px">
        <div class="hint">
          由该 CA 签发（或被反查为签发者）的证书。CA 与证书的关联由<b>签发关系</b>决定，
          改不了也无需维护：删除 CA 前要先处理这里列出的证书。<br>
          「签发方式」列显示该证书的签发者；受信任的 CA 的证书不在列表中，它们没有本地签发记录。
        </div>
        <el-table :data="caCertsDrawer.certs" v-loading="caCertsDrawer.loading"
                  size="small" border style="width: 100%">
          <el-table-column prop="id" label="ID" width="60" />
          <el-table-column label="用途" min-width="170">
            <template v-slot:default="scope">{{ typeLabel(scope.row.type) }}</template>
          </el-table-column>
          <el-table-column label="国标 ID" min-width="180">
            <template v-slot:default="scope">{{ scope.row.gbId || '-' }}</template>
          </el-table-column>
          <el-table-column label="主题（CN）" min-width="180">
            <template v-slot:default="scope">
              <el-tooltip :disabled="!subjectTip(scope.row)" :content="subjectTip(scope.row)" placement="top">
                <span class="cell-ellipsis">{{ scope.row.subjectCn || '-' }}</span>
              </el-tooltip>
            </template>
          </el-table-column>
          <el-table-column label="状态" width="100">
            <template v-slot:default="scope">
              <el-tag v-if="scope.row.revoked" size="mini" type="danger">已吊销</el-tag>
              <el-tag v-else-if="!scope.row.certPem" size="mini" type="warning">待签发</el-tag>
              <el-tag v-else-if="expiryState(scope.row) === 'expired'" size="mini" type="danger">已过期</el-tag>
              <el-tag v-else-if="expiryState(scope.row) === 'soon'" size="mini" type="warning">即将过期</el-tag>
              <span v-else style="color: #c0c4cc">-</span>
            </template>
          </el-table-column>
          <el-table-column label="签发方式" min-width="190">
            <template v-slot:default="scope">
              <el-tooltip :content="issuerTip(scope.row)" placement="top">
                <el-tag size="mini" :type="issuerTagType(scope.row)">{{ issuerText(scope.row) }}</el-tag>
              </el-tooltip>
            </template>
          </el-table-column>
          <el-table-column prop="notAfter" label="失效时间" min-width="160" />
          <el-table-column label="操作" width="90" fixed="right">
            <template v-slot:default="scope">
              <el-button type="text" size="mini" @click="gotoCertTab(scope.row)">去处理</el-button>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </el-drawer>

    <!-- ============ 导入本地身份证书（证书 + 私钥） ============ -->
    <el-dialog title="导入本地身份证书" :visible.sync="identityImportDialog.visible" width="520px" :close-on-click-modal="false">
      <el-form label-width="130px" size="small">
        <el-form-item label="用途">
          <el-tag size="small">{{ typeLabel(identityImportDialog.type) }}</el-tag>
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
    <el-dialog :title="'导入' + typeLabel(peerImportDialog.type)" :visible.sync="peerImportDialog.visible"
               width="520px" :close-on-click-modal="false">
      <el-form label-width="130px" size="small">
        <el-form-item label="用途">
          <el-tag size="small">{{ typeLabel(peerImportDialog.type) }}</el-tag>
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
      <div class="hint">对端证书仅保存公钥；即使选择了私钥文件也不会被保存。<br>
        导入时会检查签发者是否已在「CA 证书管理」里 —— 没有只提示、不拦截：是否信任由注册时的
        证书链校验实时判定，CA 可以先于证书导入，也可以后补。</div>
      <div slot="footer">
        <el-button size="mini" @click="peerImportDialog.visible = false">取消</el-button>
        <el-button size="mini" type="primary" :loading="peerImportDialog.loading" @click="submitPeerImport">导入</el-button>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import {
  generateCa, importCa, listCa, deleteCa, downloadCa, listCaCerts,
  createServerIdentity, createCsr, signPendingCsr, completePendingCsr, downloadCsr, importIdentity,
  issueFromCsr, importPeer,
  listCert, getCertPolicy, downloadCert, deleteCert,
  TYPE_SERVER_IDENTITY, TYPE_DEVICE_IDENTITY, TYPE_ISSUED_DEVICE, TYPE_TRUSTED_PLATFORM,
  TYPE_LOCAL_CA, TYPE_TRUSTED_CA, TYPE_LABELS
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
      /** 证书策略（只读）：rejectExpiredCert 决定过期证书的提示文案；verifyUpstreamCertChain 为 false（偏离默认）时顶部显示黄色告警；skipCertChainVerify 为 true 时顶部显示红色告警 */
      policy: { rejectExpiredCert: false, verifyUpstreamCertChain: true, skipCertChainVerify: false },
      formRules: {
        subjectCn: [{ required: true, message: '请输入主题 CN', trigger: 'blur' }]
      },
      issueRules: {
        caId: [{ required: true, message: '请选择签发 CA', trigger: 'change' }],
        gbId: [{ required: true, message: '请输入下级国标 ID', trigger: 'blur' }],
        csrPem: [{ required: true, message: '请粘贴 CSR 内容', trigger: 'blur' }]
      },
      caDialog: {
        visible: false, mode: 'generate', title: '生成本地根 CA', type: TYPE_LOCAL_CA,
        subjectCn: '', country: 'CN', province: '', locality: '', organization: '',
        organizationalUnit: '', remark: '', validityDays: 3650, loading: false
      },
      csrDialog: {
        visible: false, title: '创建证书请求（CSR）', loading: false, type: TYPE_DEVICE_IDENTITY,
        form: this.emptyProfile(TYPE_DEVICE_IDENTITY)
      },
      issueCsrDialog: {
        visible: false, loading: false,
        form: { caId: null, gbId: '', csrPem: '', remark: '', validityDays: 3650 }
      },
      /** 一步创建服务端证书（本平台）：密钥对在本平台生成，caId 为空即自签。 */
      serverIdentityDialog: {
        visible: false, loading: false, caId: null, validityDays: 3650,
        form: this.emptyProfile(TYPE_SERVER_IDENTITY)
      },
      completeDialog: { visible: false, loading: false, id: null, subjectCn: '' },
      /** 用本地根 CA 签发待签发的服务端证书（原地更新该记录，不新增行）。 */
      signPendingDialog: { visible: false, loading: false, id: null, subjectCn: '', caId: null, validityDays: 3650 },
      /** CA 关联证书清单（CA 列表点开「N 张」时按需拉取）。 */
      caCertsDrawer: { visible: false, loading: false, title: '', caId: null, certs: [] },
      identityImportDialog: { visible: false, loading: false, type: TYPE_SERVER_IDENTITY, gbId: '', remark: '' },
      peerImportDialog: { visible: false, loading: false, type: TYPE_TRUSTED_PLATFORM, gbId: '', remark: '' },
      files: {
        caCert: null, completeCert: null,
        identityCert: null, identityKey: null, peerCert: null
      }
    }
  },
  computed: {
    localCaList() {
      return this.caList.filter(ca => ca.type === TYPE_LOCAL_CA)
    },
    serverIdentityList() {
      return this.certList.filter(c => c.type === TYPE_SERVER_IDENTITY)
    },
    issuedDeviceList() {
      return this.certList.filter(c => c.type === TYPE_ISSUED_DEVICE)
    },
    deviceIdentityList() {
      return this.certList.filter(c => c.type === TYPE_DEVICE_IDENTITY)
    },
    trustedPlatformList() {
      return this.certList.filter(c => c.type === TYPE_TRUSTED_PLATFORM)
    },
    trustedCaList() {
      return this.caList.filter(ca => ca.type === TYPE_TRUSTED_CA)
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
     * 反而把真正该做的事（删除后重新颁发）漏掉。
     *
     * @param strictText 拒绝过期证书时的文案
     * @param looseText  不拒绝过期证书时的文案
     */
    expiredTip(strictText, looseText) {
      return (this.policy && this.policy.rejectExpiredCert) ? strictText : looseText
    },
    /** 读取证书策略（只读）；失败时按默认策略（不拒绝过期、校验上级链、不跳过链验证）渲染，不影响列表使用 */
    loadPolicy() {
      getCertPolicy().then(res => {
        const data = (res && res.data) || {}
        this.policy = {
          rejectExpiredCert: !!data.rejectExpiredCert,
          verifyUpstreamCertChain: !!data.verifyUpstreamCertChain,
          skipCertChainVerify: !!data.skipCertChainVerify,
          moduleId: data.moduleId || ''
        }
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
     * 本地根 CA 唯一性检查。
     *
     * <p>后端已有同样的守卫；提前到打开对话框之前，避免填完表单才被拒。
     * 只对 LOCAL_CA 生效：受信任的 CA 可以有多张。
     *
     * @return true 表示可以继续；false 表示已提示并应中止
     */
    checkLocalCaFree() {
      const exist = this.localCaList[0]
      if (!exist) return true
      const used = this.usedCaIds.has(exist.id)
      this.$confirm(
        '本平台已存在本地根 CA #' + exist.id + '（' + (exist.subjectCn || '未命名') + '），'
          + '本地根 CA 只保留一份。'
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
    checkServerKeyPairFree(type) {
      if (type !== TYPE_SERVER_IDENTITY) return true
      const active = this.serverIdentityList.find(c => !c.revoked)
      if (!active) return true
      // 待签发行（无证书）与已签发行分开提示：待签发行不是「占用」，而是「还差一步」，
      // 让它去删掉重来会白丢一对密钥与一份 CSR。三个出口在列表行上都有按钮。
      const text = !active.certPem
        ? '本平台已有一张待签发的服务端证书 #' + active.id + '（' + (active.subjectCn || '未命名') + '），'
          + '服务端只保留一组密钥对。请先在列表里把它签发出来（「签发」用本地根 CA，'
          + '或「回填」外部签发的证书），或删除该待签发记录后再重新创建。'
        : '本平台已有服务端证书 #' + active.id + '（' + (active.subjectCn || '未命名') + '），'
          + '服务端只保留一组密钥对。如需延长有效期或更换主题，请先删除该证书再重新创建 —— '
          + '注意新证书是新的密钥对，绑定过它的设备与级联平台需要重新导入本平台证书。'
      this.$confirm(text, '已有服务端密钥对',
        { type: 'warning', confirmButtonText: '知道了', showCancelButton: false }).catch(() => {})
      return false
    },
    /** 本平台自身的国标 ID（sip.id），作为本地服务端/客户端证书的默认国标 ID */
    loadLocalGbId() {
      getSystemConfig().then(res => {
        const sip = (res && res.data && res.data.sip) || {}
        this.localGbId = sip.id || ''
      }).catch(() => {})
    },
    /**
     * 用途是否为「设备证书」—— 决定落库时是否解析密码模块 ID 列。
     *
     * <p>注意：主题 CN 的「设备ID_密码模块ID」格式**不再**由这个判断决定。
     * 本平台签发的所有证书（服务端 / 客户端 / 根 CA）主题都按该格式默认生成，
     * 见 {@link defaultSubjectCn}。
     */
    isDeviceType(type) {
      return type === TYPE_DEVICE_IDENTITY || type === TYPE_ISSUED_DEVICE
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
     * 按附录 A 表 A.1 拼装主题：设备ID_密码模块ID，空的一段写 NULL。
     *
     * <p>证书主题里填国标 ID 是本平台的一贯做法（级联、设备注册都靠它认身份），
     * 而密码模块 ID 一栏本平台没有硬件模块、恒为全 0 —— 与其让每个入口各拼一遍、
     * 拼法还各不相同，不如统一在这里生成。用户仍可在表单里直接改主题。
     */
    composeCn(gbId, moduleId) {
      const d = (gbId || '').trim() || 'NULL'
      const m = (moduleId || '').trim() || 'NULL'
      return d + '_' + m
    },
    /**
     * 默认主题：本平台国标 ID + 22 个 0 的密码模块 ID。
     *
     * <p>国标 ID 取自系统配置（`sip.id`）。服务端证书、客户端证书、根 CA 都用它 ——
     * 三者都是本平台自己签发的身份，主题格式没有理由不一样。
     * 取不到国标 ID 时退回 `NULL_全0`（标准里空段就写 NULL），
     * 至少不生成一个格式上说不通的串。
     */
    defaultSubjectCn() {
      return this.composeCn(this.localGbId, this.defaultModuleId())
    },
    /**
     * 本地身份证书的初始表单：主题默认生成，只留一个可改的主题字段。
     *
     * <p>不再拆「国标 ID / 密码模块 ID」两个输入框 —— 它们只是默认主题的组成成分，
     * 拆出来等于把同一个值让用户填三遍，且改一处还要同步另两处。
     * 接入上级时若本平台编码不适用（另编一个防冲突），直接改主题即可。
     */
    emptyProfile(type) {
      const gbId = this.localGbId || ''
      return {
        type: type, gbId: gbId,
        subjectCn: this.defaultSubjectCn(),
        country: 'CN', province: '', locality: '',
        organization: '', organizationalUnit: '', remark: '', validityDays: 3650
      }
    },
    typeLabel(type) {
      return TYPE_LABELS[type] || type
    },
    /** 下拉标签带 #id，避免同 CN 证书无法区分 */
    caLabel(ca) {
      return '#' + ca.id + ' ' + (ca.subjectCn || '未命名')
    },
    /** 按 id 取 CA（本地根 CA 与受信任的 CA 都在 caList 里） */
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
     * 密码模块 ID 列 tooltip。
     *
     * <p>GB/T 43026—2023 表 4 序号 1「设备身份管理」要求平台能查看「设备 ID、其密码模块 ID
     * 与设备证书的对应关系」。三者中设备 ID 与证书各有一列，模块 ID 单列出来才凑齐这一组；
     * 编码规则见 GB 35114—2017 附录 B（22 位十进制）。
     */
    moduleIdTip(row) {
      if (!row || !row.moduleId) {
        return '证书主题 CN 里没有密码模块 ID（该段为 NULL）。无硬件密码模块时按附录 A 表 A.1 的约定填 NULL'
      }
      return '取自证书主题 CN 中「设备ID_密码模块ID」的后半段。'
        + '附录 B 编码规则：产品型号 4 + 类型 2 + 生产日期 8 + 批次 3 + 序号 5 = 22 位十进制'
    },
    /**
     * 签发方式文案：显示到「哪个 CA」这一级，而不只是「CA 签发」。
     *
     * <p>多上级场景下，只写「CA 签发」看不出这张证书归属哪个上级；
     * 显示 CA 的 #id 与 CN 才能与「CA 证书管理」页的 CA 对上号。
     */
    issuerText(row) {
      if (!row.certPem) return '待签发'
      if (row.caId) {
        const ca = this.caById(row.caId)
        // 自签证书现在也会关联到同公钥的 CA（反查签发者时不再对自签提前返回），
        // 因此「有 caId」不等于「非自签」—— 这里必须把「自签」显式带出来。
        if (row.selfSigned) {
          return '自签（同密钥 CA #' + row.caId + '）'
        }
        const kind = ca && ca.type === TYPE_LOCAL_CA ? '本地根 CA #' : '受信任的 CA #'
        return kind + row.caId + (ca ? '（' + (ca.subjectCn || '未命名') + '）' : '（已删除）')
      }
      return row.selfSigned ? '自签' : '签发者未导入'
    },
    /**
     * 签发方式 tag 类型。
     *
     * <p>客户端证书（本平台）必须由上级签发 —— 本地 CA 签的或自签的，上级那边没有签发记录，
     * 接入必然被拒，且失败只出现在上级、本平台日志一切正常。这类一律标红。
     */
    issuerTagType(row) {
      if (!row.certPem) return 'info'
      const ca = row.caId ? this.caById(row.caId) : null
      // 自签与「本地 CA 签发」在信任上是同一回事：上级都不认。因此 selfSigned 单独判，
      // 不能只靠 ca.type —— 自签证书的 caId 现在指向同密钥的那条 CA 记录。
      const locallyIssued = row.selfSigned || (ca && ca.type === TYPE_LOCAL_CA)
      if (locallyIssued) {
        return row.type === TYPE_DEVICE_IDENTITY ? 'danger' : 'warning'
      }
      // 有 caId 且是受信任的 CA 签发 = 正常；caId 为空又非自签 = 签发者未导入。
      // 上级证书这一栏还要看开关：关掉链校验后它不会被拒，标红是虚警，降为 warning。
      if (ca) {
        return 'success'
      }
      return (row.type === TYPE_TRUSTED_PLATFORM && !this.policy.verifyUpstreamCertChain)
        ? 'warning'
        : 'danger'
    },
    issuerTip(row) {
      if (!row.certPem) {
        return '尚未签发：该记录只有 CSR 与私钥，等待签发后回填证书'
      }
      const ca = row.caId ? this.caById(row.caId) : null
      if (ca) {
        const kind = ca.type === TYPE_LOCAL_CA ? '本地根 CA' : '受信任的 CA'
        const selfTail = row.selfSigned
          ? '。该证书是自签的，它的公钥与本平台已导入的 CA #' + ca.id
            + ' 相同（同一张证书也作为 CA 导入了一份）—— 关联成立，但它仍属「自签」'
          : ''
        const tail = row.type === TYPE_DEVICE_IDENTITY && ca.type === TYPE_LOCAL_CA
          ? '。注意：本平台作客户端时，证书必须由上级签发，本地 CA 签出的证书上级不认'
          : ''
        return '由 ' + kind + ' #' + ca.id + '（' + (ca.subjectCn || '未命名') + '）签发'
          + selfTail + tail
      }
      if (row.selfSigned) {
        return '自签：证书由它自己的私钥签署（issuer 与 subject 相同），'
          + '且本平台的 CA 列表里没有与它同公钥的记录。无 CA 的联调环境可用；'
          + '正式环境建议改用本地根 CA 签发'
      }
      // 上级平台证书这一栏的链校验由开关控制（默认开），关掉后「会不通过」是过度告警；
      // 其余各栏（下级设备证书恒开、本平台身份证书不走链校验）照旧直说。
      if (row.type === TYPE_TRUSTED_PLATFORM && !this.policy.verifyUpstreamCertChain) {
        return '签发者未导入：该证书由 ' + (row.issuerDn || '未知 CA') + ' 签发，'
          + '本平台的 CA 列表里没有它。当前已关闭上级证书链校验'
          + '（gb35114.verify-upstream-cert-chain=false），不影响级联注册；'
          + '但该项一旦改回 true 就会断链，建议把签发它的 CA 导入'
          + '「CA 证书管理 · 受信任的 CA 证书」。'
      }
      return '签发者未导入：该证书由 ' + (row.issuerDn || '未知 CA') + ' 签发，'
        + '本平台的 CA 列表里没有它。该证书仍可正常使用，但注册时的证书链校验会不通过 —— '
        + '请把签发它的 CA 导入「CA 证书管理 · 受信任的 CA 证书」。'
    },
    /** 主题变更时同步国标 ID 列（取主题里「_」前的部分，供落库与列表显示）。 */
    syncGbIdFromCn(value) {
      const f = this.csrDialog.form
      f.gbId = String(value || '').split('_')[0].trim()
    },
    syncServerIdentityGbIdFromCn(value) {
      const f = this.serverIdentityDialog.form
      f.gbId = String(value || '').split('_')[0].trim()
    },
    /**
     * 主题里的密码模块 ID 段合规性提示（附录 A 表 A.1 / 附录 B）。
     *
     * <p>只提示不拦截：后端 `requireValidDeviceCn` 才是权威校验，前端这里是为了
     * 让用户在点「生成」之前就看见问题，而不是等一次失败往返。
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
        visible: true, mode: 'generate', title: '生成本地根 CA', type: TYPE_LOCAL_CA,
        // 根 CA 的主题同样默认按附录 A 格式生成：它也是本平台签发的证书身份，
        // 没有理由和别的证书用两套命名。
        subjectCn: this.defaultSubjectCn(),
        country: 'CN', province: '', locality: '', organization: '',
        organizationalUnit: '', remark: '', validityDays: 3650, loading: false
      }
    },
    /**
     * 打开「导入受信任的 CA」对话框。
     *
     * <p>只有受信任的 CA 走导入：本地根 CA 必须持有私钥才能签发，而私钥既不允许导出、
     * 也就不存在从外部搬回来的场景 —— 那条路径由「生成本地根 CA」独占，界面不再暴露
     * 导入入口（后端 {@code importCa(LOCAL_CA)} 及其唯一性守卫仍在，只是没有调用方）。
     */
    openCaImport(type) {
      const p = type || TYPE_TRUSTED_CA
      if (p === TYPE_LOCAL_CA) {
        this.$message.warning('本地根 CA 由本平台生成，不支持导入；如需更换请先删除旧的。')
        return
      }
      this.caDialog = {
        visible: true, mode: 'import',
        title: '导入受信任的 CA',
        type: p,
        subjectCn: '', country: 'CN', province: '', locality: '', organization: '',
        organizationalUnit: '', remark: '', validityDays: 3650, loading: false
      }
      this.files.caCert = null
      if (this.$refs.caCertFile) this.$refs.caCertFile.value = ''
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
          country: this.caDialog.country,
          province: this.caDialog.province,
          locality: this.caDialog.locality,
          organization: this.caDialog.organization,
          organizationalUnit: this.caDialog.organizationalUnit,
          remark: this.caDialog.remark
        }, this.caDialog.validityDays)
          .then(() => { this.caDialog.visible = false; this.$message.success('生成成功'); this.loadCaList() })
          .finally(() => { this.caDialog.loading = false })
      } else {
        if (!this.files.caCert) {
          this.caDialog.loading = false
          this.$message.warning('请选择 CA 证书文件')
          return
        }
        // 只走受信任的 CA 这一支：本地根 CA 的导入入口已移除，故不带 keyFile。
        importCa({
          type: TYPE_TRUSTED_CA,
          remark: this.caDialog.remark,
          certFile: this.files.caCert
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
    /**
     * 点开某个 CA 的关联证书清单。
     *
     * <p>列表接口只带 certCount 一个数，明细按需拉取 —— 否则每刷一次 CA 列表都要为
     * 每张 CA 查一遍证书表。清空上一次的结果再拉，避免加载期间闪现上一个 CA 的清单。
     */
    openCaCerts(row) {
      this.caCertsDrawer = {
        visible: true, loading: true, caId: row.id,
        title: 'CA #' + row.id + '（' + (row.subjectCn || '未命名') + '）关联的证书',
        certs: []
      }
      listCaCerts(row.id).then(res => {
        this.caCertsDrawer.certs = (res && res.data) || []
      }).catch(() => {
        this.$message.warning('查询关联证书失败')
      }).finally(() => { this.caCertsDrawer.loading = false })
    },
    /**
     * 从 CA 关联清单跳到该证书所在的 tab。
     *
     * <p>清单里没有直接操作（删除）是有意的：删除在各自 tab 里有完整的前置说明
     * 与引用检查，放在抽屉里做会绕开它们。这里只负责把人送到正确的地方。
     */
    gotoCertTab(row) {
      const map = {
        SERVER_IDENTITY: 'serverIdentity',
        ISSUED_DEVICE: 'issuedDevice',
        DEVICE_IDENTITY: 'deviceIdentity',
        TRUSTED_PLATFORM: 'trustedPlatform'
      }
      const tab = map[row.type]
      if (!tab) {
        this.$message.info('该用途没有对应的证书页')
        return
      }
      this.caCertsDrawer.visible = false
      this.activeTab = tab
    },

    // ---------------- 证书列表 ----------------
    /**
     * 刷新证书列表。
     *
     * <p>各 tab 的刷新统一走这里。CA 列表不在此刷新：它只在 tab 1 的生成/导入/删除里变化，
     * 那几处已各自调用 {@link #loadCaList}；证书的「签发方式」列虽要 caList 才能把 caId
     * 翻成 CA 名称，但 CA 变了必然经过那几处，不会漏。
     */
    loadCertList() {
      this.certLoading = true
      listCert().then(res => {
        this.certList = (res && res.data) || []
      }).finally(() => { this.certLoading = false })
    },

    // ---------------- 创建 CSR ----------------
    openIdentity(type) {
      if (!this.checkServerKeyPairFree(type)) return
      this.csrDialog = {
        visible: true, title: '创建证书请求（CSR）- ' + this.typeLabel(type),
        loading: false, type: type, form: this.emptyProfile(type)
      }
      this.$nextTick(() => { if (this.$refs.csrForm) this.$refs.csrForm.clearValidate() })
    },
    submitCsr() {
      this.$refs.csrForm.validate(valid => {
        if (!valid) return
        const f = this.csrDialog.form
        if (!this.checkSubjectModuleId(f.subjectCn)) return
        this.csrDialog.loading = true
        createCsr({
          type: this.csrDialog.type,
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

    // ---------------- 待签发记录：回填 ----------------
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

    // ---------------- 待签发记录：用本地根 CA 签发 ----------------
    /**
     * 打开「用本地根 CA 签发服务端证书」。
     *
     * <p>与「回填」并列：回填用于证书已在外部签好的情况，这里用于本平台自己签。
     * 只有服务端证书能走这条路 —— 客户端证书必须由上级签发，本地签的上级不认，
     * 后端 requireLocallyIssuableType 会拒绝，前端就不给入口。
     */
    openSignPending(row) {
      this.signPendingDialog = {
        visible: true, loading: false, id: row.id, subjectCn: row.subjectCn,
        caId: this.localCaList.length ? this.localCaList[0].id : null,
        validityDays: 3650
      }
    },
    submitSignPending() {
      this.signPendingDialog.loading = true
      signPendingCsr(this.signPendingDialog.id, this.signPendingDialog.caId,
        this.signPendingDialog.validityDays)
        .then(() => {
          this.signPendingDialog.visible = false
          this.$message.success('签发成功，请把本平台证书（或签发它的 CA 证书）导入设备')
          this.loadCertList()
        })
        .finally(() => { this.signPendingDialog.loading = false })
    },

    // ---------------- 一步创建服务端证书（本平台） / 导入 ----------------
    /**
     * 打开「创建服务端证书（本平台）」。
     *
     * <p>与客户端证书不同，服务端证书由本平台自己签发（作 UAS 对 sign2 签名），
     * 所以不需要 CSR 那套「出 CSR → 上级签发 → 回填」的往返：密钥对与签名
     * 在同一个请求里完成。
     */
    openServerIdentity() {
      if (!this.checkServerKeyPairFree(TYPE_SERVER_IDENTITY)) return
      this.serverIdentityDialog = {
        visible: true, loading: false,
        caId: this.localCaList.length ? this.localCaList[0].id : null,
        validityDays: 3650,
        form: this.emptyProfile(TYPE_SERVER_IDENTITY)
      }
      this.$nextTick(() => {
        if (this.$refs.serverIdentityForm) this.$refs.serverIdentityForm.clearValidate()
      })
    },
    submitServerIdentity() {
      this.$refs.serverIdentityForm.validate(valid => {
        if (!valid) return
        const f = this.serverIdentityDialog.form
        if (!this.checkSubjectModuleId(f.subjectCn)) return
        this.serverIdentityDialog.loading = true
        createServerIdentity({
          type: TYPE_SERVER_IDENTITY,
          gbId: f.gbId,
          subjectCn: f.subjectCn || f.gbId,
          country: f.country,
          province: f.province,
          locality: f.locality,
          organization: f.organization,
          organizationalUnit: f.organizationalUnit,
          remark: f.remark
        }, this.serverIdentityDialog.caId, f.validityDays)
          .then(() => {
            this.serverIdentityDialog.visible = false
            this.$message.success('创建成功，请把本平台证书（或签发它的 CA 证书）导入设备')
            this.loadCertList()
          })
          .finally(() => { this.serverIdentityDialog.loading = false })
      })
    },
    openIdentityImport(type) {
      if (!this.checkServerKeyPairFree(type)) return
      this.identityImportDialog = { visible: true, loading: false, type: type, gbId: '', remark: '' }
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
        type: this.identityImportDialog.type,
        gbId: this.identityImportDialog.gbId,
        remark: this.identityImportDialog.remark
      }, this.files.identityCert, this.files.identityKey)
        .then(() => { this.identityImportDialog.visible = false; this.$message.success('导入成功'); this.loadCertList() })
        .finally(() => { this.identityImportDialog.loading = false })
    },
    openPeerImport(type) {
      this.peerImportDialog = { visible: true, loading: false, type: type, gbId: '', remark: '' }
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
        type: this.peerImportDialog.type,
        gbId: this.peerImportDialog.gbId,
        remark: this.peerImportDialog.remark
      }, this.files.peerCert)
        .then(res => {
          this.peerImportDialog.visible = false
          this.$message.success('导入成功')
          // 签发者 CA 尚未导入时后端会给一句提示（不拦导入）。用 warning 而非 success 展示，
          // 因为这句话指向的是「设备注册时会被拒」这个稍后才发作的问题，容易被划过去。
          const warn = res && res.data && res.data.importWarning
          if (warn) {
            this.$notify({ title: '导入成功，但有一处需要处理', message: warn, type: 'warning', duration: 0 })
          }
          this.loadCertList()
        })
        .finally(() => { this.peerImportDialog.loading = false })
    },

    // ---------------- 生命周期 ----------------
    /**
     * 删除证书。这是让一张证书失效的**唯一**入口（没有单独的「吊销」按钮）。
     *
     * <p>删除与吊销对「能不能接入」是等价的：设备自报的证书按公钥指纹反查本表，
     * 命中已吊销记录拒绝，**压根查不到记录同样拒绝** —— 两条路都通向"用不了"。
     * 保留一个入口是为了不出现"吊销了但记录还在、占着唯一性守卫"这类中间态。
     */
    confirmDeleteCert(row) {
      this.$confirm('确认删除该证书？本地身份证书的私钥将一并删除，且不可恢复。'
        + '若仍被设备或平台绑定，后端会拒绝删除，请先在这些设备/平台的编辑页解除绑定。',
      '提示', { type: 'warning' })
        .then(() => {
          deleteCert(row.id).then(() => { this.$message.success('删除成功'); this.loadCertList() })
        }).catch(() => {})
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
/* 一栏里再分小节时的标题（CA 证书管理页的两栏） */
.section-title {
  font-size: 13px;
  font-weight: 600;
  color: #303133;
  margin: 12px 0 6px;
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
