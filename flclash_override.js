// ============================================================
// 用户自定义配置区域 (修改这里即可，无需翻看下方代码)
// ============================================================

// 1. 自定义规则列表：
const MY_RULES = [
  
  "RULE-SET,private,DIRECT",
  
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

  "GEOIP,LAN,DIRECT",
  "GEOIP,PRIVATE,DIRECT",

  // --- 兜底规则 -> 指向：1. 快速服务 ---
  "MATCH,1. 快速服务"
];

// ============================================================
// 核心逻辑区域 (以下代码负责组装配置，通常无需修改)
// ============================================================

function main(config) {
  const allNames = (config.proxies ?? []).map(proxy => proxy.name);
  const sources = Object.keys(config["proxy-providers"] ?? {});
  if (!allNames.length && !sources.length) return config;

  const originalGroups = config["proxy-groups"] ?? [];
  const groupNames = new Set([...allNames, ...sources, ...originalGroups.map(group => group.name)]);
  const fast = reserveName(groupNames, "1. 快速服务");
  const restricted = reserveName(groupNames, "2. 限制服务");
  const fastAuto = reserveName(groupNames, "3. 快速自动");
  const restrictedAuto = reserveName(groupNames, "4. 限制自动");
  const manual = reserveName(groupNames, "5. 原始节点");
  const groupAliases = new Map([
    ["1. 快速服务", fast], ["2. 限制服务", restricted],
    ["3. 快速自动", fastAuto], ["4. 限制自动", restrictedAuto],
    ["5. 原始节点", manual]
  ]);

  const restrictedFilter = "香港|台湾";
  const restrictedNames = allNames.filter(name => !/香港|台湾/.test(name));
  const use = sources.length ? { use: sources } : {};
  const restrictedUse = sources.length ? { ...use, "exclude-filter": restrictedFilter } : {};
  const auto = {
    type: "url-test",
    url: "https://www.gstatic.com/generate_204",
    interval: 300,
    timeout: 2000,
    tolerance: 50,
    "empty-fallback": "REJECT"
  };
  const groups = [
    {
      name: fast,
      type: "select",
      proxies: [fastAuto, manual, ...allNames],
      ...use
    },
    {
      name: restricted,
      type: "select",
      proxies: [restrictedAuto, manual, ...restrictedNames],
      ...restrictedUse
    },
    {
      name: fastAuto,
      ...auto,
      proxies: allNames,
      ...use
    },
    {
      name: restrictedAuto,
      ...auto,
      proxies: restrictedNames.length || sources.length ? restrictedNames : ["REJECT"],
      ...restrictedUse
    },
    {
      name: manual,
      type: "select",
      proxies: allNames,
      "empty-fallback": "REJECT",
      ...use
    }
  ];

  // 4. 定义 Rule Providers (规则集)
  const ruleProviders = {
    "special_services": {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/d-sun-cs/clash-scripts@main/special_services.txt",
      interval: 86400
    },
    "reject": {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt",
      interval: 86400
    },
    "lancidr": {
      type: "http",
      behavior: "ipcidr",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt",
      interval: 86400
    },
    "private": {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt",
      interval: 86400
    },
    "direct": {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt",
      interval: 86400
    },
    "cn": {
      type: "http",
      behavior: "domain",
      url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.yaml",
      interval: 86400
    },
    "cncidr": {
      type: "http",
      behavior: "ipcidr",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt",
      interval: 86400
    }
  };

  // 保留订阅规则集的名称和类型，供 DNS、子规则等继续引用。
  const providers = { ...config["rule-providers"] };
  const providerNames = new Set(Object.keys(providers));
  const providerPaths = new Set(
    [...Object.values(providers), ...Object.values(config["proxy-providers"] ?? {})]
      .filter(provider => provider.path)
      .map(provider => normalizePath(provider.path))
  );
  const providerAliases = new Map();
  for (const [name, provider] of Object.entries(ruleProviders)) {
    const alias = reserveName(providerNames, "flclash-override-" + name);
    const cache = reserveName(providerPaths, "ruleset/" + alias + ".yaml");
    providers[alias] = { ...provider, path: "./" + cache };
    providerAliases.set(name, alias);
  }

  const rules = MY_RULES.map(rule => {
    const parts = rule.replace(/(^|\()RULE-SET,\s*([^,)]+)/g, (match, prefix, name) => {
      const alias = providerAliases.get(name.trim());
      return alias ? prefix + "RULE-SET," + alias : match;
    }).split(",");
    const target = parts.length - (parts[parts.length - 1].trim() === "no-resolve" ? 2 : 1);
    parts[target] = groupAliases.get(parts[target].trim()) ?? parts[target];
    return parts.join(",");
  });

  return {
    ...config,
    "proxy-groups": [...groups, ...originalGroups],
    "rule-providers": providers,
    rules,
    sniffer: config.sniffer ?? {
      enable: true,
      "parse-pure-ip": true,
      "override-destination": true,
      sniff: {
        TLS: { ports: [443, 8443] },
        QUIC: { ports: [443, 8443] }
      }
    }
  };
}

function reserveName(used, preferred) {
  let name = preferred;
  for (let suffix = 2; used.has(name); suffix++) {
    name = preferred + "-" + suffix;
  }
  used.add(name);
  return name;
}

function normalizePath(path) {
  const parts = [];
  for (const part of path.toLowerCase().split(/[\\/]+/)) {
    if (part === ".." && parts.length && parts[parts.length - 1] !== "..") {
      parts.pop();
    } else if (part && part !== ".") {
      parts.push(part);
    }
  }
  return parts.join("/");
}
