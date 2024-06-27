const axios = require("axios").default;
const dotenv = require("dotenv");
const fs = require("fs/promises");
const jwt = require("jsonwebtoken");
const uuid = require("uuid");

dotenv.config();

const issuanceDate = new Date();
const issuanceTime = Math.floor(issuanceDate.getTime() / 1000);
const expirationDate = new Date((issuanceTime + 30) * 1000);
const expirationTime = Math.floor(expirationDate.getTime() / 1000);

async function getVerifiableCredential() {
    return JSON.parse(await fs.readFile("verifiable-credential.json", "utf8"));
}

function createVerifiablePresentationJwtPayload(verifiableCredential) {
    return {
        iss: verifiableCredential.issuer,
        sub: verifiableCredential.issuer,
        iat: issuanceTime,
        nbf: issuanceTime,
        exp: expirationTime,
        nonce: uuid.v4(),
        jti: uuid.v4(),
        vp: {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            id: "urn:uuid:" + uuid.v4(),
            type: ["VerifiablePresentation"],
            holder: verifiableCredential.issuer,
            verifiableCredential: [verifiableCredential]
        }
    };
}

function createVerifiablePresentationJwt(verifiablePresentationJwtPayload, privateKey) {
    const options = {
        algorithm: "RS256",
        header: {
            typ: "JWT",
            alg: "RS256",
            kid: verifiablePresentationJwtPayload.iss
        }
    };

    return jwt.sign(verifiablePresentationJwtPayload, privateKey, options);
}

function createVerifiablePresentation(verifiablePresentationJwtPayload, verifiablePresentationJwt, verifiableCredential) {
    return {
        "sub": verifiablePresentationJwtPayload.sub,
        "iat": verifiablePresentationJwtPayload.iat,
        "nonce": verifiablePresentationJwtPayload.nonce,
        "vp": {
            "id": verifiablePresentationJwtPayload.vp.id,
            "holder": verifiablePresentationJwtPayload.vp.holder
        },
        "verifiableCredential": [verifiableCredential],
        "holder": verifiablePresentationJwtPayload.iss,
        "id": verifiablePresentationJwtPayload.jti,
        "type": ["VerifiablePresentation"],
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "issuanceDate": issuanceDate.toISOString(),
        "expirationDate": expirationDate.toISOString(),
        "proof": {
            "type": "JwtProof2020",
            "jwt": verifiablePresentationJwt
        }
    };
}

async function requestAccessToken(vcVerifierTokenUrl, verifiablePresentation) {
    const params = new URLSearchParams();
    params.append("grant_type", "vp_token");
    params.append("vp_token", btoa(JSON.stringify(verifiablePresentation)).replace(/={1,2}$/, ""));
    params.append("presentation_submission", "");
    params.append("scope", "");

    const config = {
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        }
    };

    const response = await axios.post(vcVerifierTokenUrl, params, config);
    return response.data.access_token;
}

async function requestStreetlights(contextBrokerUrl, accessToken) {
    const config = {
        headers: {
            Authorization: `Bearer ${accessToken}`,
            Link: `<${process.env.CONTEXT_URL}>; rel="http://www.w3.org/ns/json-ld#context"; type="application/ld+json"`
        }
    };

    const response = await axios.get(`${contextBrokerUrl}/ngsi-ld/v1/entities?type=Streetlight`, config);
    return response.data;
}

async function main() {
    try {
        const verifiableCredential = await getVerifiableCredential();
        const verifiablePresentationJwtPayload = createVerifiablePresentationJwtPayload(verifiableCredential);
        const verifiablePresentationJwt = createVerifiablePresentationJwt(verifiablePresentationJwtPayload, process.env.PRIVATE_KEY);
        const verifiablePresentation = createVerifiablePresentation(verifiablePresentationJwtPayload, verifiablePresentationJwt, verifiableCredential);
        const accessToken = await requestAccessToken(process.env.VC_VERIFIER_TOKEN_URL, verifiablePresentation);
        const streetlights = await requestStreetlights(process.env.CONTEXT_BROKER_URL, accessToken);
        console.log(streetlights);
    } catch(error) {
        console.error(error);
    }
}

main();
