// ============================================================
// 用户自定义配置区域 (修改这里即可，无需翻看下方代码)
// ============================================================

// 1. 【限制服务】规则列表：
// 这里的域名会强制走“限制服务”节点（通常用于 AI 服务）
const MY_AI_RULES = [
  "DOMAIN-SUFFIX,clients6.google.com,限制服务",
  "DOMAIN,gemini.google.com,限制服务",
  "DOMAIN,notebooklm.google.com,限制服务",
  "DOMAIN,one.google.com,限制服务",
  "DOMAIN-SUFFIX,chatgpt.com,限制服务",
  "DOMAIN-SUFFIX,openai.com,限制服务",
  "DOMAIN-SUFFIX,claude.com,限制服务",
  "DOMAIN-SUFFIX,claude.ai,限制服务"
];

// 2. 【DIRECT】直连规则列表：
// 这里的域名/关键字会强制直连（不走代理）
const MY_DIRECT_RULES = [
  "DOMAIN-KEYWORD,dockerproxy,DIRECT", // 示例：取消注释即可生效
  // "DOMAIN-KEYWORD,daocloud,DIRECT"
];

// ============================================================
// 核心逻辑区域 (以下代码负责组装配置，通常无需修改)
// ============================================================

function main(config) {
  // 1. 获取订阅中的所有代理节点
  const proxies = config.proxies || [];

  // 提取所有节点的名称
  const allProxyNames = proxies.map(p => p.name);

  // 2. 生成【限制服务】的节点列表
  // 逻辑：过滤掉名字里包含 "香港" 或 "台湾" 的节点
  const restrictedProxyNames = proxies
    .filter(p => {
      const name = p.name;
      return !name.includes('香港') && !name.includes('台湾');
    })
    .map(p => p.name);

  // 3. 定义策略组
  const groups = [
    {
      // 【快速服务】：包含所有节点
      name: "快速服务",
      type: "url-test",
      url: 'https://www.gstatic.com/generate_204',
      interval: 300,
      timeout: 2000,
      tolerance: 50,
      proxies: allProxyNames.length > 0 ? allProxyNames : ["DIRECT"]
    },
    {
      // 【限制服务】：只包含非港台节点
      name: "限制服务",
      type: "url-test",
      url: 'https://www.gstatic.com/generate_204',
      interval: 300,
      timeout: 2000,
      tolerance: 50,
      proxies: restrictedProxyNames.length > 0 ? restrictedProxyNames : ["DIRECT"]
    },
    {
      // 【原始】：手动选择
      name: "原始",
      type: "select",
      proxies: allProxyNames.length > 0 ? allProxyNames : ["DIRECT"]
    }
  ];

  // 4. 定义 Rule Providers (Loyalsoldier 规则集)
  const ruleProviders = {
    "reject": {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt",
      path: "./ruleset/reject.yaml",
      interval: 86400
    },
    "lancidr": {
      type: "http",
      behavior: "ipcidr",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt",
      path: "./ruleset/lancidr.yaml",
      interval: 86400
    },
    "private": {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt",
      path: "./ruleset/private.yaml",
      interval: 86400
    },
    "direct": {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt",
      path: "./ruleset/direct.yaml",
      interval: 86400
    },
    "cncidr": {
      type: "http",
      behavior: "ipcidr",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt",
      path: "./ruleset/cncidr.yaml",
      interval: 86400
    }
  };

  // 5. 定义规则 (Rules)
  // 使用 ...语法 将顶部的自定义数组展开插入到规则列表中
  const rules = [
    // --- 1. 插入顶部的自定义 AI/限制规则 ---
    ...MY_AI_RULES,

    // --- 2. 广告拦截 ---
    "RULE-SET,reject,REJECT",

    // --- 3. 插入顶部的自定义直连规则 ---
    ...MY_DIRECT_RULES,

    // --- 4. 局域网与私有地址 (必须直连) ---
    "RULE-SET,lancidr,DIRECT",
    "RULE-SET,private,DIRECT",
    "GEOIP,LAN,DIRECT",
    "GEOIP,PRIVATE,DIRECT",

    // --- 5. 中国大陆域名与 IP (白名单模式核心) ---
    "RULE-SET,direct,DIRECT",
    "RULE-SET,cncidr,DIRECT",
    "GEOIP,CN,DIRECT",

    // --- 6. 兜底规则 ---
    "MATCH,快速服务"
  ];

  // 6. 将新的配置覆盖回 config 对象
  config["proxy-groups"] = groups;
  config["rules"] = rules;
  config["rule-providers"] = ruleProviders;

  return config;
}
