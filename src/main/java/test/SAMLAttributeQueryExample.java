/*
 * Licensed to the University Corporation for Advanced Internet Development, 
 * Inc. (UCAID) under one or more contributor license agreements.  See the 
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package test;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.annotation.Nonnull;
import javax.net.ssl.SSLContext;

import net.shibboleth.utilities.java.support.security.Type4UuidIdentifierGenerationStrategy;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;

import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.cryptacular.util.CertUtil;
import org.cryptacular.util.KeyPairUtil;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.messaging.context.InOutOperationContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeQuery;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.soap.client.http.HttpSOAPClient;
import org.opensaml.soap.messaging.context.SOAP11Context;
import org.opensaml.soap.soap11.Body;
import org.opensaml.soap.soap11.Envelope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Send an attribute query to an IdP.
 */
public class SAMLAttributeQueryExample {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(SAMLAttributeQueryExample.class);

    /** Constructor. */
    public SAMLAttributeQueryExample() {
    }

    /**
     * Send an attribute query to an IdP.
     * 
     * @param args program arguments
     * @throws Exception if an error occurs
     */
    public static void main(String[] args) throws Exception {
        SAMLAttributeQueryExample attributeQueryExample = new SAMLAttributeQueryExample();
        attributeQueryExample.sendAttributeQuery();
    }

    /**
     * Send an attribute query to an IdP.
     * 
     * @throws Exception if an error occurs
     */
    public void sendAttributeQuery() throws Exception {

        String endpoint = "https://idp.example.org:8443/idp/profile/SAML2/SOAP/AttributeQuery";

        String requester = "https://sp.example.org/shibboleth";

        String idpCertificateFile = "/opt/shib/idp/credentials/idp.crt";
        String clientTLSPrivateKeyFile = "/opt/local/etc/shibboleth/sp-key.pem";
        String clientTLSCertificateFile = "/opt/local/etc/shibboleth/sp-cert.pem";

        String principalName = "jdoe";
        String expectedAttributeFriendlyName = "mail";
        String expectedAttributeValue = "jdoe@example.org";

        InitializationService.initialize();

        AttributeQuery attributeQuery = buildAttributeQueryRequest(requester, principalName);

        Envelope envelope = buildSOAP11Envelope(attributeQuery);

        HttpClient httpClient = buildHttpClient(idpCertificateFile, clientTLSPrivateKeyFile, clientTLSCertificateFile);

        BasicParserPool parserPool = new BasicParserPool();
        parserPool.initialize();

        HttpSOAPClient httpSoapClient = new HttpSOAPClient(httpClient, parserPool);

        InOutOperationContext context = buildInOutOperationContext(envelope);

        httpSoapClient.send(endpoint, context);

        Envelope soapResponse = context.getInboundMessageContext().getSubcontext(SOAP11Context.class).getEnvelope();
        System.out.println("SOAP Response was:");
        System.out.println(SerializeSupport.prettyPrintXML(soapResponse.getDOM()));

        // Verify the response was a success and the expected attribute was returned.
        if (verifyResponse(soapResponse, principalName, expectedAttributeFriendlyName, expectedAttributeValue)) {
            System.out.println("Response completed successfully.");
        } else {
            System.err.println("Response not completed successfully.");
        }
    }

    /**
     * Builds a basic attribute query.
     * 
     * @param requester the requester
     * @param principalName the principal name
     * @return the attribute query
     */
    @Nonnull public static AttributeQuery buildAttributeQueryRequest(@Nonnull final String requester,
            @Nonnull final String principalName) {
        XMLObjectBuilderFactory bf = XMLObjectProviderRegistrySupport.getBuilderFactory();
        final SAMLObjectBuilder<Issuer> issuerBuilder =
                (SAMLObjectBuilder<Issuer>) bf.<Issuer> getBuilderOrThrow(Issuer.DEFAULT_ELEMENT_NAME);
        final Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(requester);

        final SAMLObjectBuilder<NameID> nameIdBuilder =
                (SAMLObjectBuilder<NameID>) bf.<NameID> getBuilderOrThrow(NameID.DEFAULT_ELEMENT_NAME);
        final NameID nameId = nameIdBuilder.buildObject();
        nameId.setValue(principalName);
        nameId.setFormat(NameID.PERSISTENT);

        final SAMLObjectBuilder<Subject> subjectBuilder =
                (SAMLObjectBuilder<Subject>) bf.<Subject> getBuilderOrThrow(Subject.DEFAULT_ELEMENT_NAME);
        final Subject subject = subjectBuilder.buildObject();
        subject.setNameID(nameId);

        final SAMLObjectBuilder<AttributeQuery> queryBuilder =
                (SAMLObjectBuilder<AttributeQuery>) bf
                        .<AttributeQuery> getBuilderOrThrow(AttributeQuery.DEFAULT_ELEMENT_NAME);
        final AttributeQuery query = queryBuilder.buildObject();
        query.setID(new Type4UuidIdentifierGenerationStrategy().generateIdentifier());
        query.setIssueInstant(new DateTime());
        query.setIssuer(issuer);
        query.setSubject(subject);
        query.setVersion(SAMLVersion.VERSION_20);

        return query;
    }

    /**
     * Build the envelope.
     * 
     * @param payload the payload
     * @return the envelope
     */
    public static Envelope buildSOAP11Envelope(XMLObject payload) {
        XMLObjectBuilderFactory bf = XMLObjectProviderRegistrySupport.getBuilderFactory();
        Envelope envelope =
                (Envelope) bf.getBuilder(Envelope.DEFAULT_ELEMENT_NAME).buildObject(Envelope.DEFAULT_ELEMENT_NAME);
        Body body = (Body) bf.getBuilder(Body.DEFAULT_ELEMENT_NAME).buildObject(Body.DEFAULT_ELEMENT_NAME);

        body.getUnknownXMLObjects().add(payload);
        envelope.setBody(body);

        return envelope;
    }

    /**
     * Build the HTTP client.
     * 
     * @param idpCertificateFile path to idp certificate file
     * @param clientPrivateKeyFile path to client private key file
     * @param clientCertificateFile path to client certificate file
     * @return the HTTP client
     * @throws Exception if an error occurs
     */
    @Nonnull public static HttpClient buildHttpClient(@Nonnull final String idpCertificateFile,
            @Nonnull final String clientPrivateKeyFile, @Nonnull final String clientCertificateFile) throws Exception {

        X509Certificate idpCert = CertUtil.readCertificate(idpCertificateFile);
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        trustStore.setCertificateEntry("idp", idpCert);

        PrivateKey clientPrivateKey = KeyPairUtil.readPrivateKey(clientPrivateKeyFile);
        X509Certificate clientCert = CertUtil.readCertificate(clientCertificateFile);
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setKeyEntry("me", clientPrivateKey, "secret".toCharArray(), new Certificate[] {clientCert});

        SSLContextBuilder sslContextBuilder = SSLContexts.custom();
        sslContextBuilder.loadTrustMaterial(trustStore);
        sslContextBuilder.loadKeyMaterial(keyStore, "secret".toCharArray());
        SSLContext sslcontext = sslContextBuilder.build();

        CloseableHttpClient httpClient = HttpClients.custom().setSslcontext(sslcontext).build();

        return httpClient;
    }

    /**
     * Build the {@link InOutOperationContext}.
     * 
     * @param envelope the envelope
     * @return the context
     */
    @Nonnull public static InOutOperationContext buildInOutOperationContext(@Nonnull final Envelope envelope) {
        SOAP11Context soap11Ctx = new SOAP11Context();
        soap11Ctx.setEnvelope(envelope);

        MessageContext msgCtx = new MessageContext();
        msgCtx.addSubcontext(soap11Ctx);

        InOutOperationContext inOutOpCtx = new InOutOperationContext() {};
        inOutOpCtx.setOutboundMessageContext(msgCtx);

        return inOutOpCtx;
    }

    /**
     * Verify that response was a success and the expected attribute was returned.
     * 
     * @param soapResponse the response
     * @param principal the principal
     * @param expectedAttributeFriendlyName the expected attribute name
     * @param expectedAttributeValue the expected attribute value
     * @return whether or not the response was a success and the expected attribute was returned
     */
    public static boolean verifyResponse(Envelope soapResponse, String principal, String expectedAttributeFriendlyName,
            String expectedAttributeValue) {
        //
        Response response = (Response) soapResponse.getBody().getUnknownXMLObjects().get(0);
        if (!response.getStatus().getStatusCode().getValue().equals(StatusCode.SUCCESS_URI)) {
            System.err.println("Response was not a success.");
            return false;
        }

        Assertion assertion = response.getAssertions().get(0);

        if (!assertion.getSubject().getNameID().getValue().equals(principal)) {
            System.err.println("Subject does not match.");
            return false;
        }

        boolean expectedAttributeWasReturned = false;
        for (AttributeStatement attributeStatement : assertion.getAttributeStatements()) {
            for (Attribute attribute : attributeStatement.getAttributes()) {
                for (XMLObject value : attribute.getAttributeValues()) {
                    if (attribute.getFriendlyName().equals(expectedAttributeFriendlyName)) {
                        if (((XSString) value).getValue().equals(expectedAttributeValue)) {
                            expectedAttributeWasReturned = true;
                        }
                    }
                }
            }
        }

        if (!expectedAttributeWasReturned) {
            System.err.println("Response did not contain the expected attribute.");
            return false;
        }

        return true;
    }
}
