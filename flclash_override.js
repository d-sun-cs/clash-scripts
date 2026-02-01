// ============================================================
// 用户自定义配置区域 (修改这里即可，无需翻看下方代码)
// ============================================================

// 1. 自定义规则列表：
const MY_RULES = [
  // 广告拦截
  "RULE-SET,reject,REJECT",

  // 特殊服务 (AI 服务等)
  "RULE-SET,special_services,限制服务",

  "DOMAIN-KEYWORD,dockerproxy,DIRECT", 
  "DOMAIN-KEYWORD,daocloud,DIRECT",
  "DOMAIN,learn.microsoft.com,DIRECT",

  // --- 中国大陆域名与 IP (白名单模式核心) ---
  // "RULE-SET,direct,DIRECT",
  "RULE-SET,cn,DIRECT",
  "RULE-SET,cncidr,DIRECT",
  "GEOIP,CN,DIRECT",

  // --- 局域网与私有地址 (必须直连) ---
  "RULE-SET,lancidr,DIRECT",
  "RULE-SET,private,DIRECT",
  "GEOIP,LAN,DIRECT",
  "GEOIP,PRIVATE,DIRECT",

  // --- 兜底规则 ---
  "MATCH,快速服务"
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

  // 4. 定义 Rule Providers (规则集)
  const ruleProviders = {
    "special_services": {
      type: "http",
      behavior: "domain",
      url: "https://raw.githubusercontent.com/d-sun-cs/clash-scripts/main/special_services.txt",
      path: "./ruleset/special_services.yaml",
      interval: 86400
    },
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
    "cn": {
      type: "http",
      behavior: "domain",
      url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.yaml",
      path: "./provider/rule-set/cn_domain.yaml",
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
  // const rules = MY_RULES;

  // 6. 将新的配置覆盖回 config 对象
  config["proxy-groups"] = groups;
  // config["rules"] = rules;
  config["rules"] = MY_RULES;
  config["rule-providers"] = ruleProviders;

  return config;
}
