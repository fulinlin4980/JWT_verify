#pragma once

#include<QMap>
#include<QJsonDocument>
#include<QJsonObject>

// 定义一个类型别名：参数初始化列表，键为 QString，值为 QVariant
using ParamInitList = QMap<QString, QVariant>;

namespace SJwt
{

	/**
	 * JWT 支持的签名算法类型
	 */
	enum class SAlgorithm
	{
		NONE = 0,
		HS256,
		HS384,
		HS512,
		RS256,
		RS384,
		RS512,
		ES256,
		ES384,
		ES512,
		UNKN,   // 未知算法
		TERM,   // 结束标记（可能用于内部处理）
	};

	// 将算法枚举转换为字符串形式
	static inline const char* alg_to_str(SAlgorithm alg) noexcept
	{
		switch (alg) {
		case SAlgorithm::HS256: return "HS256";
		case SAlgorithm::HS384: return "HS384";
		case SAlgorithm::HS512: return "HS512";
		case SAlgorithm::RS256: return "RS256";
		case SAlgorithm::RS384: return "RS384";
		case SAlgorithm::RS512: return "RS512";
		case SAlgorithm::ES256: return "ES256";
		case SAlgorithm::ES384: return "ES384";
		case SAlgorithm::ES512: return "ES512";
		case SAlgorithm::TERM:  return "TERM";
		case SAlgorithm::NONE:  return "NONE";
		case SAlgorithm::UNKN:  return "UNKN";
		default:               Q_ASSERT_X(0, __FUNCTION__, "Unknown Algorithm");
		};
		return "UNKN";
	}

	/**
	 * 将字符串转换为对应的算法枚举
	 * 字符串比较大小写不敏感
	 */
	static inline SAlgorithm str_to_alg(const QAnyStringView alg) noexcept
	{
		if (!alg.length()) return SAlgorithm::UNKN;

		if (!QAnyStringView::compare(alg, "NONE"))  return  SAlgorithm::NONE;
		if (!QAnyStringView::compare(alg, "HS256")) return  SAlgorithm::HS256;
		if (!QAnyStringView::compare(alg, "HS384")) return  SAlgorithm::HS384;
		if (!QAnyStringView::compare(alg, "HS512")) return  SAlgorithm::HS512;
		if (!QAnyStringView::compare(alg, "RS256")) return  SAlgorithm::RS256;
		if (!QAnyStringView::compare(alg, "RS384")) return  SAlgorithm::RS384;
		if (!QAnyStringView::compare(alg, "RS512")) return  SAlgorithm::RS512;
		if (!QAnyStringView::compare(alg, "ES256")) return  SAlgorithm::ES256;
		if (!QAnyStringView::compare(alg, "ES384")) return  SAlgorithm::ES384;
		if (!QAnyStringView::compare(alg, "ES512")) return  SAlgorithm::ES512;

		return SAlgorithm::UNKN;
	}

	/**
	 * JWT 标准注册字段（Claims）
	 */
	enum registered_claims
	{
		expiration = 0,		/*!< 过期时间(exp) */
		not_before,			/*!< 生效时间(nbf) */
		issuer,				/*!< 签发者(iss) */
		audience,			/*!< 接收方(aud) */
		issued_at,			/*!< 签发时间(iat) */
		subject,			/*!< 主题(sub) */
		jti,				/*!< JWT ID 唯一标识(jti) */
	};

	/**
	 * 将注册字段枚举转换为对应字符串
	 */
	static inline const char* reg_claims_to_str(registered_claims claim) noexcept
	{
		switch (claim) {
		case registered_claims::expiration: return "exp";
		case registered_claims::not_before: return "nbf";
		case registered_claims::issuer:     return "iss";
		case registered_claims::audience:   return "aud";
		case registered_claims::issued_at:  return "iat";
		case registered_claims::subject:    return "sub";
		case registered_claims::jti:        return "jti";
		default:                            Q_ASSERT_X(0, __FUNCTION__, "Not a registered claim");
		};
		return "unkn";
	}

	// JWT 对象类，封装 JWT 的构建、解析和验证功能
	class SJwtObject
	{
	public:
		// 表示 JWT 状态的枚举
		enum class Status
		{
			Ok,                 /*!< 正常 */
			Expired,            /*!< 已过期 */
			AlgorithmError,     /*!< 算法错误 */
			JwrFormatError,     /*!< 格式错误 */
			Invalid,            /*!< 非法 JWT */
		};

	public:
		SJwtObject() = default; // 默认构造函数

		// 构造函数：指定算法、payload 数据和密钥
		SJwtObject(SAlgorithm alg, const QJsonObject& playload, QAnyStringView secret);

		// 添加标准 claim 字段
		SJwtObject& addClaim(SJwt::registered_claims claim, const QVariant& value);

		// 添加自定义 claim 字段
		SJwtObject& addClaim(QAnyStringView claim, const QVariant& value);

		// 移除标准 claim 字段
		SJwtObject& removeClaim(SJwt::registered_claims claim);

		// 移除自定义 claim 字段
		SJwtObject& removeClaim(QAnyStringView claim);

		// 判断是否包含指定标准字段
		bool hasClaim(SJwt::registered_claims claim);

		// 判断是否包含指定自定义字段
		bool hasClaim(QAnyStringView claim);

		// 获取 JWT 当前状态
		Status status() const { return m_status; }

		// 判断 JWT 是否有效
		bool isValid() const { return m_status == Status::Ok; }

		// 获取出错时的错误信息
		const QString& errorString() const { return m_errorString; }

		// 获取当前的密钥
		const QByteArray& secret() const { return m_secret; }

		// 设置密钥
		void setSecret(const QByteArray& sec) { m_secret = sec; }

		// 获取当前的算法
		SAlgorithm algorithm() const { return m_alg; }

		// 设置使用的算法
		void setAlgorithm(SAlgorithm alg) { m_alg = alg; }

		// 获取 Header 的 JSON 对象引用
		QJsonObject& header();

		// 设置 Header 内容
		void setHeader(const QJsonObject& header) { m_headerJson = header; }

		// 获取 Payload 的 JSON 对象引用
		QJsonObject& payload();

		// 设置 Payload 内容
		void setPayload(const QJsonObject& payload) { m_payloadJson = payload; }

		// 计算签名内容（Base64(header) + "." + Base64(payload) + secret）
		QByteArray signature() const;

		// 获取 Base64 编码后的 Header
		QByteArray headerBase64() const;

		// 获取 Base64 编码后的 Payload
		QByteArray payloadBase64() const;

		// 获取完整 JWT 字符串
		QByteArray jwt();

		// 解码 JWT（轻量级，不含错误状态信息）
		static SJwtObject decode1(const QByteArray& jwt, SAlgorithm alg, QAnyStringView secret);

		// 解码 JWT（带错误信息和状态）
		static SJwtObject decode(const QByteArray& jwt, SAlgorithm alg, const QByteArray& secret);

	private:
		SAlgorithm m_alg{};           // 当前算法
		QByteArray m_secret{};        // 签名用密钥（或称盐值）
		QJsonObject m_headerJson;     // Header 部分
		QJsonObject m_payloadJson;    // Payload 部分
		QString m_errorString{};      // 错误信息
		Status m_status{ Status::Ok }; // 当前状态
	};

}; // namespace SJwt
