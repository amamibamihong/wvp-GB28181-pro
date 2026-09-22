package com.genersoft.iot.vmp.gb35114.crypto;

import com.genersoft.iot.vmp.gb35114.sip.Gb35114Exception;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 401 挑战头的 golden 测试。
 *
 * <p>golden 值取自 gb28181-rs {@code security35114::headers} 的测试常量，
 * 期望算法串与 {@link Gb35114HeaderUtil#CAPABILITY_ALGORITHM} 一致 ——
 * 标准 §C.3 b) 要求挑战里的 {@code algorithm} 是「从设备上报能力中选出的结果」，
 * 且必须是<b>完整四段</b>（A / H / S / SI）；只回 {@code A:SM2;H:SM3}
 * 会被部分设备（如海康）判为协商不一致而拒绝后续信令。
 */
class Gb35114ChallengeGoldenTest {

    private static final String GOLDEN_RANDOM1 = "PRAIIbutDbd5x/NKsbwwYw==";

    @Test
    void buildChallengeGolden() {
        assertEquals(
                "Bidirection algorithm=\"" + Gb35114HeaderUtil.CAPABILITY_ALGORITHM
                        + "\", random1=\"" + GOLDEN_RANDOM1 + "\"",
                Gb35114HeaderUtil.buildChallenge(Gb35114HeaderUtil.Mode.Bidirection, GOLDEN_RANDOM1));
        assertEquals(
                "Unidirection algorithm=\"" + Gb35114HeaderUtil.CAPABILITY_ALGORITHM
                        + "\", random1=\"" + GOLDEN_RANDOM1 + "\"",
                Gb35114HeaderUtil.buildChallenge(Gb35114HeaderUtil.Mode.Unidirection, GOLDEN_RANDOM1));
    }

    @Test
    void parseChallengeRejectsDigest() {
        assertThrows(Gb35114Exception.class, () ->
                Gb35114HeaderUtil.parseChallenge("Digest realm=\"3402000000\", nonce=\"abc\""));
        assertThrows(Gb35114Exception.class, () ->
                Gb35114HeaderUtil.parseChallenge("Unidirection algorithm=\"A:SM2\""));
    }
}
