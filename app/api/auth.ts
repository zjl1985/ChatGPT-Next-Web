import { NextRequest } from "next/server";
import { getServerSideConfig } from "../config/server";
import md5 from "spark-md5";
import { ACCESS_CODE_PREFIX, ModelProvider } from "../constant";
import CryptoJS from "crypto-js";

function decrypt(base64String: string) {
  try {
    base64String = aesDecrypt(base64String);
    // 用base64进行一个解密
    let byteArray = Buffer.from(base64String, "base64");
    // 高低位互换
    const byteArrayExpire = Buffer.from([...byteArray].reverse());
    // 转成Long
    let expireTime = Number(byteArrayExpire.readBigInt64BE());
    return new Date(expireTime * 1000);
  } catch (e) {
    console.error(e);
    return new Date(0);
  }
}

function aesDecrypt(encrypted: string) {
  const key = "nY1Df+xsP0OTasFH";
  const decoded = CryptoJS.enc.Base64.parse(encrypted);
  const iv = CryptoJS.lib.WordArray.create(decoded.words.slice(0, 4)); // the first 16 bytes are the IV
  const encrypted_data = CryptoJS.lib.WordArray.create(decoded.words.slice(4)); // the rest is the encrypted data
  const cipher = CryptoJS.AES.decrypt(
    { ciphertext: encrypted_data },
    CryptoJS.enc.Utf8.parse(key),
    { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 },
  );
  const decrypted = cipher.toString(CryptoJS.enc.Utf8);
  return decrypted;
}

function getIP(req: NextRequest) {
  let ip = req.ip ?? req.headers.get("x-real-ip");
  const forwardedFor = req.headers.get("x-forwarded-for");

  if (!ip && forwardedFor) {
    ip = forwardedFor.split(",").at(0) ?? "";
  }

  return ip;
}

function parseApiKey(bearToken: string) {
  const token = bearToken.trim().replaceAll("Bearer ", "").trim();
  const isApiKey = !token.startsWith(ACCESS_CODE_PREFIX);

  return {
    accessCode: isApiKey ? "" : token.slice(ACCESS_CODE_PREFIX.length),
    apiKey: isApiKey ? token : "",
  };
}

export function auth(req: NextRequest, modelProvider: ModelProvider) {
  const authToken = req.headers.get("Authorization") ?? "";

  // check if it is openai api key or user token
  const { accessCode, apiKey } = parseApiKey(authToken);

  const hashedCode = md5.hash(accessCode ?? "").trim();

  const serverConfig = getServerSideConfig();
  console.log("[Auth] allowed hashed codes: ", [...serverConfig.codes]);
  console.log("[Auth] got access code:", accessCode);
  console.log("[Auth] hashed access code:", hashedCode);
  console.log("[User IP] ", getIP(req));
  console.log("[Time] ", new Date().toLocaleString());

  if (!apiKey && accessCode) {
    const expireTime = decrypt(accessCode);
    console.log("[Auth] expire time: ", expireTime.toLocaleString());
    if (expireTime < new Date()) {
      return {
        error: true,
        msg: "access code expired",
      };
    }
  }

  if (serverConfig.hideUserApiKey && !!apiKey) {
    return {
      error: true,
      msg: "you are not allowed to access with your own api key",
    };
  }

  // if user does not provide an api key, inject system api key
  if (!apiKey) {
    const serverConfig = getServerSideConfig();

    const systemApiKey =
      modelProvider === ModelProvider.GeminiPro
        ? serverConfig.googleApiKey
        : serverConfig.isAzure
        ? serverConfig.azureApiKey
        : serverConfig.apiKey;
    if (systemApiKey) {
      console.log("[Auth] use system api key");
      req.headers.set("Authorization", `Bearer ${systemApiKey}`);
    } else {
      console.log("[Auth] admin did not provide an api key");
    }
  } else {
    console.log("[Auth] use user api key");
  }

  return {
    error: false,
  };
}
