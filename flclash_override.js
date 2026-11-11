// ============================================================
// 用户自定义配置区域 (修改这里即可，无需翻看下方代码)
// ============================================================

// 1. 自定义规则列表：
const MY_RULES = [
  // 广告拦截
  "RULE-SET,reject,REJECT",

  // 特殊服务 (AI 服务等) -> 指向：2. 限制服务
  "RULE-SET,special_services,2. 限制服务",

  "DOMAIN-KEYWORD,dockerproxy,DIRECT", // 示例：取消注释即可生效
  "DOMAIN,learn.microsoft.com,DIRECT",
  // "DOMAIN-KEYWORD,daocloud,DIRECT",

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

  // --- 兜底规则 -> 指向：1. 快速服务 ---
  "MATCH,1. 快速服务"
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

  // 兜底：如果节点为空，则填入 DIRECT 避免报错
  const allNames = allProxyNames.length > 0 ? allProxyNames : ["DIRECT"];
  const restrictedNames = restrictedProxyNames.length > 0 ? restrictedProxyNames : ["DIRECT"];

  // 3. 定义策略组 (加入数字前缀控制面板排序)
  const groups = [
    {
      // 1. 手动选择的快速服务 (默认包含自动、原始、以及所有可用节点)
      name: "1. 快速服务",
      type: "select",
      proxies: ["3. 快速自动", "5. 原始节点", ...allNames]
    },
    {
      // 2. 手动选择的限制服务 (默认包含自动、原始、以及所有非港台节点)
      name: "2. 限制服务",
      type: "select",
      proxies: ["4. 限制自动", "5. 原始节点", ...restrictedNames]
    },
    {
      // 3. 自动优选的快速服务
      name: "3. 快速自动",
      type: "url-test",
      url: 'https://www.gstatic.com/generate_204',
      interval: 300,
      timeout: 2000,
      tolerance: 50,
      proxies: allNames
    },
    {
      // 4. 自动优选的限制服务
      name: "4. 限制自动",
      type: "url-test",
      url: 'https://www.gstatic.com/generate_204',
      interval: 300,
      timeout: 2000,
      tolerance: 50,
      proxies: restrictedNames
    },
    {
      // 5. 原始所有节点的手动选择集合
      name: "5. 原始节点",
      type: "select",
      proxies: allNames
    }
  ];

  // 4. 定义 Rule Providers (规则集)
  const ruleProviders = {
    "special_services": {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/d-sun-cs/clash-scripts@main/special_services.txt",
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

  // 5. 将新的配置覆盖回 config 对象
  config["proxy-groups"] = groups;
  config["rules"] = MY_RULES;
  config["rule-providers"] = ruleProviders;
  
  // 6. 解决openai相关dns解析问题
  config.sniffer = {
    enable: true,
    "parse-pure-ip": true,
    "override-destination": true,
    sniff: {
      TLS: { ports: [443, 8443] },
      QUIC: { ports: [443, 8443] }
    }
  };  

  return config;
}
