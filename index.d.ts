/**
 * Interface for lib/saml (Banno/node-saml).  It differs from the original
 * designed for auth0/node-saml to include the enhancements for supporting
 * a full SAML 2.0 Response in all signing modes.
 */
 declare module '@banno/saml' {
    export interface SamlAttributes {
        [key: string]: string;
    }
  
    export interface KeyInfoProvider {
        getKeyInfo(key: string, prefix: string): string;
    }
  
    export interface SamlOpts {
        authnContextClassRef?: string;
        attributes?: SamlAttributes;
        audiences?: string | string[];
        cert: Buffer;
        digestAlgorithm?: string;
        encryptionAlgorithm?: string;
        encryptionCert?: Buffer;
        encryptionPublicKey?: Buffer;
        holderOfKeyProofSecret?: string;
        includeAttributeNameFormat?: boolean;
        inResponseTo?: string;
        issuer?: string;
        key: Buffer;
        keyEncryptionAlgorighm?: string; // sic https://github.com/auth0/node-xml-encryption/issues/17
        keyInfoProvider?: KeyInfoProvider;
        lifetimeInSeconds?: number;
        nameIdentifier?: string;
        nameIdentifierFormat?: string;
        prefix?: string;
        recipient?: string;
        sessionIndex?: string;
        signatureAlgorithm?: string;
        signatureNamespacePrefix?: string;
        subjectConfirmationMethod?: string;
        typedAttributes?: boolean;
        uid?: string;
        responseUid?: string;
        xpathToNodeBeforeSignature?: string;
        createSignedSamlResponse?: boolean;
        responseSigningLevel?: string;
        destination?: string;
    }
  
    export namespace Saml11 {
        function create(opts: SamlOpts, cb?: (err: Error | null, result: any[], proofSecret: Buffer) => void): any;
    }
  
    export namespace Saml20 {
        function create(opts: SamlOpts, cb?: (err: Error | null, signed: string) => void): any;
    }
  }
  