const select = require('xml-crypto').xpath;
const SignedXml = require('xml-crypto').SignedXml;
const FileKeyInfo = require('xml-crypto').FileKeyInfo;
const fs = require('fs');
const XMLSerializer = require('xmldom').XMLSerializer;
const DOMParser = require('xmldom').DOMParser;
const serializer = new XMLSerializer();

class DSGenerator {
    constructor() {
        this.keyFile = fs.readFileSync('./certs/privatekey.key').toString();
        this.certFile = './certs/certificate.crt';
        const samplexml = fs.readFileSync('./certs/sample.xml').toString();
        const outputFile = './certs/signedXml.xml';
        /*Generate Digital Signature*/
        generateDS(samplexml, outputFile, this.keyFile, this.certFile);
    };
};

class MyKeyInfo {
    constructor(crt) {
        this.fileData = crt
    }
    getKeyInfo(key, prefix) {
        prefix = prefix || ''
        prefix = prefix ? prefix + ':' : prefix
        return '<' + prefix + 'X509Data><X509Certificate xmlns="http://www.w3.org/2000/09/xmldsig#">' + this.getKey() + '</X509Certificate><X509IssuerSerial xmlns="http://www.w3.org/2000/09/xmldsig#"><X509IssuerName>' + 'Issuer Name' + '</X509IssuerName><X509SerialNumber>' + 'Serial Number' + '</X509SerialNumber></X509IssuerSerial></' + prefix + 'X509Data>'
    }
    getKey(keyInfo) {
        return fs.readFileSync(this.fileData).toString()
    }
};

const generateDS = (samplexml, outputFile, keyFile, certFile) => {
    const {
        UniqueId,
        xml
    } = injectDynamicValues(samplexml);
    console.log(`Generating Digital Signature...`);
    /*Sign input XML with signature and validate it*/
    signAndValidateXml(xml, keyFile, certFile)
        .then((success) => {
            fs.writeFile(outputFile, success, (err, success) => {
                if (err) return err;
                console.log(`Signed XML Is In '${outputFile}' And UniqueId Is '${UniqueId}'.`);
            });
        }).catch((err) => {
            console.log(`Error While Generating Digital Signature ${err}.`);
        })
};

const signAndValidateXml = (samplexml, keyFile, certFile) => {
    return new Promise((resolve, reject) => {
        let signature = new SignedXml()
        const xpath = '/Envelope/Body[@Id="body"]'
        signature.keyInfoProvider = new MyKeyInfo(certFile)
        signature.signingKey = keyFile;
        signature.addReference(xpath)
        signature.computeSignature(samplexml, {
            location: {
                reference: "/Envelope/Header/Security",
                action: "append"
            }
        })

        const signedXMLReq = signature.getSignedXml();
        console.log(`XML Signed Succesfully.
Validating Signature...`);
        
        /*Validating Signature*/
        const validateXmlStatus = validateXml(signedXMLReq, certFile);
        if (validateXmlStatus) {
            console.log(`Signature Is Valid.`);
            resolve(signedXMLReq);
        } else {
            reject(`Signature is Invalid.`);
        }
    });
};
const validateXml = (xml, certFile) => {
    const doc = new DOMParser().parseFromString(xml);
    const signatureElement = select(doc, "/*/*/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
    const signature = new SignedXml();
    signature.keyInfoProvider = new FileKeyInfo(certFile);
    signature.loadSignature(signatureElement.toString());
    const status = signature.checkSignature(xml);

    if (!status) {
        return signature.validationErrors;
    } else {
        return status;
    }
};
const injectDynamicValues = (xml) => {
    const doc = new DOMParser().parseFromString(xml);
    const UniqueId = "SomePrefix-" + Math.floor(Math.random() * 900) + 100;
    const currentDate = getISODate();

    const keyValueObj = {
        "UniqueId": UniqueId,
        "CreationDateTime": currentDate
    }
    for (key in keyValueObj) {
        doc.documentElement.getElementsByTagName(key).item(0).firstChild.textContent = keyValueObj[key];
    }

    return {
        UniqueId: UniqueId,
        xml: serializer.serializeToString(doc)
    }
};
const getISODate = () => {
    const cDate = new Date().toISOString().split(".");
    return cDate[0].concat("." + cDate[1].replace("Z", ""));
}

module.exports = DSGenerator;