/*-
 * ---license-start
 * EU-Federation-Gateway-Service / efgs-federation-gateway
 * ---
 * Copyright (C) 2020 - 2021 Ubique Innovation AG and all other contributors
 * ---
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ---license-end
 */

package eu.interop.federationgateway.filter;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import eu.interop.federationgateway.TestData;
import eu.interop.federationgateway.config.EfgsProperties;
import eu.interop.federationgateway.repository.CertificateRepository;
import eu.interop.federationgateway.repository.DiagnosisKeyBatchRepository;
import eu.interop.federationgateway.repository.DiagnosisKeyEntityRepository;
import eu.interop.federationgateway.testconfig.EfgsTestKeyStore;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.Base64;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@Slf4j
@SpringBootTest
@RunWith(SpringRunner.class)
@ContextConfiguration(classes = EfgsTestKeyStore.class)
public class CertAuthFilterTestWithFullCert {
  @Autowired
  private WebApplicationContext context;

  @Autowired
  private EfgsProperties properties;

  @Autowired
  private DiagnosisKeyEntityRepository diagnosisKeyEntityRepository;

  @Autowired
  private DiagnosisKeyBatchRepository diagnosisKeyBatchRepository;

  @Autowired
  private CertificateAuthentificationFilter certFilter;

  @Autowired
  private CertificateRepository certificateRepository;

  private MockMvc mockMvc;
  
  @Before
  public void setup() throws CertificateException, NoSuchAlgorithmException, IOException, OperatorCreationException,
      InvalidKeyException, SignatureException, KeyStoreException {
    TestData.insertCertificatesForAuthentication(certificateRepository);

    diagnosisKeyEntityRepository.deleteAll();
    diagnosisKeyBatchRepository.deleteAll();
    properties.getCertAuth().getHeaderFields().setCalculateHash(true);

    mockMvc = MockMvcBuilders.webAppContextSetup(context).addFilter(certFilter).build();
  }

  @Test
  public void testRequestHashCertificate() throws Exception {
    mockMvc.perform(get("/diagnosiskeys/download/s").accept("application/protobuf; version=1.0")
        .header(properties.getCertAuth().getHeaderFields().getFullCert(),
            Base64.getEncoder().encodeToString(TestData.validAuthenticationCertificate.getEncoded()))
        .header(properties.getCertAuth().getHeaderFields().getDistinguishedName(),
            "O=Test Firma GmbH,O=XXX,C=DE,U=Abteilung XYZ,TR=test"))
        .andExpect(mvcResult -> {
          Assert.assertEquals("DE",
              mvcResult.getRequest().getAttribute(CertificateAuthentificationFilter.REQUEST_PROP_COUNTRY));
        });
  }

  @Test
  public void testRequestHashCertificateFromUrlEncodedPem() throws Exception {
    String base64Der = Base64.getEncoder().encodeToString(TestData.validAuthenticationCertificate.getEncoded());
    int start = 0;
    int len = 64;
    int length = base64Der.length();
    StringBuilder sb = new StringBuilder();
    sb.append("-----BEGIN CERTIFICATE-----\n");
    while (start + len < length) {
      sb.append(base64Der.substring(start, start + len));
      sb.append("\n");
      start += len;
    }
    if (start < length) {
      sb.append(base64Der.substring(start, length));
      sb.append("\n");
    }
    sb.append("-----END CERTIFICATE-----\n");

    mockMvc.perform(get("/diagnosiskeys/download/s").accept("application/protobuf; version=1.0")
        .header(properties.getCertAuth().getHeaderFields().getFullCert(),
            URLEncoder.encode(sb.toString(), StandardCharsets.UTF_8))
        .header(properties.getCertAuth().getHeaderFields().getDistinguishedName(),
            "O=Test Firma GmbH,O=XXX,C=DE,U=Abteilung XYZ,TR=test"))
        .andExpect(mvcResult -> {
          Assert.assertEquals("DE",
              mvcResult.getRequest().getAttribute(CertificateAuthentificationFilter.REQUEST_PROP_COUNTRY));
        });
  }

  @Test
  public void testRequestHashCertificateFromUrlEncodedPemWithWindowsLineEnding() throws Exception {
    String base64Der = Base64.getEncoder().encodeToString(TestData.validAuthenticationCertificate.getEncoded());
    int start = 0;
    int len = 64;
    int length = base64Der.length();
    StringBuilder sb = new StringBuilder();
    sb.append("-----BEGIN CERTIFICATE-----\r\n");
    while (start + len < length) {
      sb.append(base64Der.substring(start, start + len));
      sb.append("\r\n");
      start += len;
    }
    if (start < length) {
      sb.append(base64Der.substring(start, length));
      sb.append("\r\n");
    }
    sb.append("-----END CERTIFICATE-----\r\n");

    mockMvc.perform(get("/diagnosiskeys/download/s").accept("application/protobuf; version=1.0")
        .header(properties.getCertAuth().getHeaderFields().getFullCert(),
            URLEncoder.encode(sb.toString(), StandardCharsets.UTF_8))
        .header(properties.getCertAuth().getHeaderFields().getDistinguishedName(),
            "O=Test Firma GmbH,O=XXX,C=DE,U=Abteilung XYZ,TR=test"))
        .andExpect(mvcResult -> {
          Assert.assertEquals("DE",
              mvcResult.getRequest().getAttribute(CertificateAuthentificationFilter.REQUEST_PROP_COUNTRY));
        });
  }

  @Test
  public void testRequestHashCertificateFromUrlEncodedPemWithEscapedLineEndings() throws Exception {
    String base64Der = Base64.getEncoder().encodeToString(TestData.validAuthenticationCertificate.getEncoded());
    int start = 0;
    int len = 64;
    int length = base64Der.length();
    StringBuilder sb = new StringBuilder();
    sb.append("-----BEGIN CERTIFICATE-----\\n");
    while (start + len < length) {
      sb.append(base64Der.substring(start, start + len));
      sb.append("\\n");
      start += len;
    }
    if (start < length) {
      sb.append(base64Der.substring(start, length));
      sb.append("\\n");
    }
    sb.append("-----END CERTIFICATE-----\\n");

    mockMvc.perform(get("/diagnosiskeys/download/s").accept("application/protobuf; version=1.0")
        .header(properties.getCertAuth().getHeaderFields().getFullCert(), sb.toString())
        .header(properties.getCertAuth().getHeaderFields().getDistinguishedName(),
            "O=Test Firma GmbH,O=XXX,C=DE,U=Abteilung XYZ,TR=test"))
        .andExpect(mvcResult -> {
          Assert.assertEquals("DE",
              mvcResult.getRequest().getAttribute(CertificateAuthentificationFilter.REQUEST_PROP_COUNTRY));
        });
  }

  @Test
  public void testRequestHashCertificateFromUrlEncodedPemWithEscapedWindowsLineEndings() throws Exception {
    String base64Der = Base64.getEncoder().encodeToString(TestData.validAuthenticationCertificate.getEncoded());
    int start = 0;
    int len = 64;
    int length = base64Der.length();
    StringBuilder sb = new StringBuilder();
    sb.append("-----BEGIN CERTIFICATE-----\\r\\n");
    while (start + len < length) {
      sb.append(base64Der.substring(start, start + len));
      sb.append("\\r\\n");
      start += len;
    }
    if (start < length) {
      sb.append(base64Der.substring(start, length));
      sb.append("\\r\\n");
    }
    sb.append("-----END CERTIFICATE-----\\r\\n");

    mockMvc.perform(get("/diagnosiskeys/download/s").accept("application/protobuf; version=1.0")
        .header(properties.getCertAuth().getHeaderFields().getFullCert(), sb.toString())
        .header(properties.getCertAuth().getHeaderFields().getDistinguishedName(),
            "O=Test Firma GmbH,O=XXX,C=DE,U=Abteilung XYZ,TR=test"))
        .andExpect(mvcResult -> {
          Assert.assertEquals("DE",
              mvcResult.getRequest().getAttribute(CertificateAuthentificationFilter.REQUEST_PROP_COUNTRY));
        });
  }
}
