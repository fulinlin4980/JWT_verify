# SJwt - 基于 Qt 的 JSON Web Token（JWT）处理库

`SJwt` 是一个基于 Qt 的轻量级 JSON Web Token（JWT）实现，支持多种算法签名、解析和验证功能，适用于在 Qt 项目中进行用户身份验证和安全数据传输。

---

## ✨ 功能特点

- ✅ 支持标准 JWT 格式解析与生成
- ✅ 支持注册字段的增删查
- ✅ 支持过期时间验证（`exp` claim）
- ✅ 支持多种签名算法
- ✅ 支持 Base64 编解码
- ✅ 易于集成到 Qt 项目中

---

## 🔐 支持的签名算法

| 枚举值       | 描述                     |
|--------------|--------------------------|
| `HS256`      | HMAC + SHA-256           |
| `HS384`      | HMAC + SHA-384           |
| `HS512`      | HMAC + SHA-512           |
| `RS256`      | SHA3-256 (模拟 RSA)      |
| `RS384`      | SHA3-384                 |
| `RS512`      | SHA3-512                 |
| `ES256`      | Keccak-256               |
| `ES384`      | Keccak-384               |
| `ES512`      | Keccak-512               |

---

## 📦 安装与集成

确保项目中启用了 Qt 的以下模块：

- `QtCore`
- `QtJson`
- `QtCrypto`（或包含 `QCryptographicHash`）

将 `SJwt.h` 和 `SJwt.cpp` 添加到你的 Qt 项目中即可使用。

---

## 🛠️ 使用示例

### 创建 JWT

```cpp
#include "SJwt.h"
using namespace SJwt;

QJsonObject payload;
payload.insert("sub", "user123");
payload.insert("exp", QDateTime::currentDateTime().addSecs(3600).toString(Qt::ISODate));

SJwtObject jwt(SAlgorithm::HS256, payload, "my_secret_key");

qDebug() << "Token: " << jwt.jwt();
```
## 解码与验证 JWT
```cpp
SJwtObject parsed = SJwtObject::decode(token, SAlgorithm::HS256, "my_secret_key");

if (parsed.isValid()) {
    qDebug() << "解析成功！Payload:" << parsed.payload();
} else {
    qDebug() << "JWT 无效，错误信息：" << parsed.errorString();
}
```
## 📌 注册字段支持（Claim）
可使用枚举或字符串添加标准字段：

```cpp
jwt.addClaim(SJwt::registered_claims::iss, "my_app");
jwt.addClaim("custom_key", "custom_value");
```
支持的标准字段（registered_claims）包括：
+ iss：发行者（Issuer）
+ sub：主题（Subject）
+ aud：接收者（Audience）
+ exp：过期时间（Expiration Time）
+ nbf：不早于时间（Not Before）
+ iat：签发时间（Issued At）
+ jti：JWT 唯一标识

## 🧪 JWT 结构说明
### 生成的 JWT 格式如下：
```scss

<base64url(header)>.<base64url(payload)>.<signature>
```
### 例如：
```eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiZXhwIjoiMjAyNS0wNS0wNlQxMjozMDowMCJ9.58ae...```
## ⚠️ 注意事项
当前未实现对 RSA/EC 私钥签名，仅模拟哈希算法，非生产级安全实现。
生产环境请使用 OpenSSL 结合 Qt 实现更严格的密钥处理。

## 📄 License
MIT License
