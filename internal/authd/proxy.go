// Package authd 实现 hatch-authd 凭证代理服务。
//
// 安全模型：
//   1. Agent 只获得代理令牌（surrogate token），无实际权限
//   2. 真实凭证存储在本服务中（运行在 Agent 容器之外）
//   3. 请求通过 Sentinel 审批、即将离开 VM 时，即时注入真实凭证
//   4. Agent 全程接触不到明文密钥
package authd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Credential 表示一条存储的真实凭证。
type Credential struct {
	ID        string    // 凭证 ID（如 "gmail-oauth"）
	Type      string    // 凭证类型（"oauth_token", "api_key"）
	Value     string    // 真实凭证值
	Scope     []string  // 权限范围
	CreatedAt time.Time
}

// SurrogateToken 是发放给 Agent 的代理令牌。
type SurrogateToken struct {
	Token     string    // 代理令牌值（无实际权限）
	CredID    string    // 关联的凭证 ID
	ExpiresAt time.Time // 过期时间
}

// Proxy 是凭证代理的核心服务。
type Proxy struct {
	mu sync.RWMutex

	// 真实凭证存储（key = credential ID）
	credentials map[string]*Credential

	// 代理令牌映射（key = surrogate token string）
	surrogates map[string]*SurrogateToken

	// 已注入的请求日志（审计追踪）
	injectionLog []InjectionRecord

	logger func(string)
}

// InjectionRecord 记录一次凭证注入。
type InjectionRecord struct {
	Timestamp time.Time
	CredID    string
	RequestID string
	DstHost   string
}

// NewProxy 创建凭证代理实例。
func NewProxy(logger func(string)) *Proxy {
	if logger == nil {
		logger = func(s string) {}
	}
	return &Proxy{
		credentials: make(map[string]*Credential),
		surrogates:  make(map[string]*SurrogateToken),
		logger:      logger,
	}
}

// AddCredential 添加真实凭证。
func (p *Proxy) AddCredential(id, credType, value string, scope []string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.credentials[id] = &Credential{
		ID:        id,
		Type:      credType,
		Value:     value,
		Scope:     scope,
		CreatedAt: time.Now(),
	}
	p.logger(fmt.Sprintf("[authd] 凭证已存储: %s (type=%s, scope=%v)", id, credType, scope))
}

// IssueSurrogate 发放代理令牌给 Agent。
//
// 代理令牌是无实际权限的占位符。
// 即使 Agent 被诱导打印它，也只会得到无用信息。
func (p *Proxy) IssueSurrogate(credID string, ttl time.Duration) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, ok := p.credentials[credID]; !ok {
		return "", fmt.Errorf("凭证 ID 不存在: %s", credID)
	}

	// 生成随机代理令牌
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("生成代理令牌失败: %w", err)
	}
	token := "surrogate_" + hex.EncodeToString(tokenBytes)

	p.surrogates[token] = &SurrogateToken{
		Token:     token,
		CredID:    credID,
		ExpiresAt: time.Now().Add(ttl),
	}

	p.logger(fmt.Sprintf("[authd] 发放代理令牌: cred=%s, ttl=%v", credID, ttl))
	return token, nil
}

// Resolve 将代理令牌解析为真实凭证。
//
// 此函数只在请求通过 Sentinel 审批后、即将离开 VM 时调用。
// 这是 Agent 接触真实凭证的唯一路径，且不由 Agent 触发。
func (p *Proxy) Resolve(surrogateToken string) (*Credential, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	st, ok := p.surrogates[surrogateToken]
	if !ok {
		return nil, fmt.Errorf("无效的代理令牌")
	}

	if time.Now().After(st.ExpiresAt) {
		return nil, fmt.Errorf("代理令牌已过期")
	}

	cred, ok := p.credentials[st.CredID]
	if !ok {
		return nil, fmt.Errorf("关联凭证不存在")
	}

	p.logger(fmt.Sprintf("[authd] 凭证解析: surrogate→%s", st.CredID))
	return cred, nil
}

// InjectCredential 将真实凭证注入到出站请求中。
// 此函数由 Sentinel 在网络边界调用，不由 Agent 调用。
func (p *Proxy) InjectCredential(req *http.Request, surrogateToken, requestID string) error {
	cred, err := p.Resolve(surrogateToken)
	if err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// 根据凭证类型注入到请求头
	switch cred.Type {
	case "oauth_token":
		req.Header.Set("Authorization", "Bearer "+cred.Value)
	case "api_key":
		req.Header.Set("X-API-Key", cred.Value)
	default:
		// 通用注入
		req.Header.Set("X-Auth-Credential", cred.Value)
	}

	// 记录注入日志（审计追踪）
	p.injectionLog = append(p.injectionLog, InjectionRecord{
		Timestamp: time.Now(),
		CredID:    cred.ID,
		RequestID: requestID,
		DstHost:   req.URL.Host,
	})

	p.logger(fmt.Sprintf("[authd] 凭证注入完成: cred=%s, dst=%s, req=%s",
		cred.ID, req.URL.Host, requestID))
	return nil
}

// RevokeSurrogate 吊销代理令牌。
func (p *Proxy) RevokeSurrogate(token string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.surrogates, token)
	p.logger(fmt.Sprintf("[authd] 代理令牌已吊销: %s...%s",
		token[:12], token[len(token)-4:]))
}

// GetInjectionLog 返回注入日志（审计用）。
func (p *Proxy) GetInjectionLog() []InjectionRecord {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make([]InjectionRecord, len(p.injectionLog))
	copy(result, p.injectionLog)
	return result
}

// ListCredentials 返回凭证元信息（不含真实值）。
func (p *Proxy) ListCredentials() []struct {
	ID    string
	Type  string
	Scope []string
} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]struct {
		ID    string
		Type  string
		Scope []string
	}, 0, len(p.credentials))

	for _, cred := range p.credentials {
		result = append(result, struct {
			ID    string
			Type  string
			Scope []string
		}{
			ID:    cred.ID,
			Type:  cred.Type,
			Scope: cred.Scope,
		})
	}
	return result
}

// ValidateTokenFormat 检查令牌格式是否为代理令牌。
// 用于在请求出站前拦截携带非代理令牌的请求。
func ValidateTokenFormat(token string) bool {
	return strings.HasPrefix(token, "surrogate_")
}
