import net from "node:net";
import dns from "node:dns";
import { createHash, timingSafeEqual } from "node:crypto";

// ---------------------------------------------------------------- 配置
// 环境变量的名字保持不变（SOCKS_PORT、SOCKS_USER ……）：Railway 上的变量就是通过这些名字传进来的。

const 监听端口 = Number(process.env.SOCKS_PORT) || 1080;
const 用户名 = process.env.SOCKS_USER || "";
const 密码 = process.env.SOCKS_PASS || "";
const 需要认证 = Boolean(用户名 && 密码);

// 不设置账号和密码，就会变成对整个互联网开放的代理，
// 所以现在必须明确声明（ALLOW_OPEN=1）才允许这样运行。
const 允许开放 = process.env.ALLOW_OPEN === "1";
// 仅用于本地测试：允许连接回环地址和内网地址。
const 允许内网 = process.env.ALLOW_PRIVATE_DESTINATIONS === "1";

const 最大连接数 = Number(process.env.MAX_CONNECTIONS) || 400;
const 握手超时毫秒 = Number(process.env.HANDSHAKE_TIMEOUT_MS) || 10000;
const 连接超时毫秒 = Number(process.env.CONNECT_TIMEOUT_MS) || 10000;
const 解析超时毫秒 = Number(process.env.DNS_TIMEOUT_MS) || 5000;
const 空闲超时毫秒 = Number(process.env.IDLE_TIMEOUT_MS) || 300000;

// 最容易招来滥用投诉的端口（垃圾邮件、SMB/RDP/telnet 扫描）。
const 默认屏蔽端口 = [23, 25, 135, 137, 138, 139, 445, 465, 587, 2525, 3389];

function 解析屏蔽端口(原始值) {
  const 值 = (原始值 || "").trim();
  if (!值) return new Set(默认屏蔽端口);
  if (值.toLowerCase() === "none") return new Set();
  return new Set(
    值
      .split(",")
      .map((片段) => Number(片段.trim()))
      .filter((端口) => Number.isInteger(端口) && 端口 > 0 && 端口 < 65536)
  );
}
const 屏蔽端口 = 解析屏蔽端口(process.env.BLOCKED_PORTS);

if (!需要认证 && !允许开放) {
  console.error("拒绝启动：没有设置 SOCKS_USER 和 SOCKS_PASS（只有确实需要开放代理时，才设置 ALLOW_OPEN=1）");
  process.exit(1);
}

// ---------------------------------------------------------------- 工具函数

const 摘要 = (内容) => createHash("sha256").update(内容, "utf8").digest();
const 安全比较 = (甲, 乙) => timingSafeEqual(摘要(甲), 摘要(乙));
const 延迟 = (毫秒) => new Promise((完成) => setTimeout(完成, 毫秒));

function 是内网IPv4(段) {
  const [甲, 乙, 丙] = 段;
  if (甲 === 0 || 甲 === 10 || 甲 === 127) return true;
  if (甲 === 100 && 乙 >= 64 && 乙 <= 127) return true; // 运营商级 NAT / Railway 内部网络
  if (甲 === 169 && 乙 === 254) return true; // 链路本地地址，云平台元数据服务
  if (甲 === 172 && 乙 >= 16 && 乙 <= 31) return true;
  if (甲 === 192 && 乙 === 168) return true;
  if (甲 === 192 && 乙 === 0 && 丙 === 0) return true;
  if (甲 === 198 && (乙 === 18 || 乙 === 19)) return true;
  return 甲 >= 224;
}

// 把 IPv6 文本展开成 8 个 16 位分组（支持 "::" 压缩写法和结尾的点分 IPv4）。
// 客户端用地址类型 4 发来的是 16 个原始字节，下面会拼成"不压缩"的写法（0:0:0:0:0:0:0:1），
// 所以不能只比较 "::1" 这样的字符串：必须先展开，再判断。
function 展开IPv6(文本) {
  let 主机 = 文本.toLowerCase().split("%")[0];
  const 点分 = /^(.*:)(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(主机);
  if (点分) {
    const 四段 = 点分.slice(2).map(Number);
    if (四段.some((数) => 数 > 255)) return null;
    主机 = `${点分[1]}${((四段[0] << 8) | 四段[1]).toString(16)}:${((四段[2] << 8) | 四段[3]).toString(16)}`;
  }
  const 两半 = 主机.split("::");
  if (两半.length > 2) return null;
  const 头部 = 两半[0] ? 两半[0].split(":") : [];
  const 尾部 = 两半.length === 2 && 两半[1] ? 两半[1].split(":") : [];
  const 补零 = 两半.length === 2 ? 8 - 头部.length - 尾部.length : 0;
  if (补零 < 0) return null;
  const 分组 = [...头部, ...Array(补零).fill("0"), ...尾部].map((片段) => parseInt(片段, 16));
  if (分组.length !== 8 || 分组.some((数) => !Number.isInteger(数) || 数 < 0 || 数 > 0xffff)) return null;
  return 分组;
}

function 是内网IPv6(地址) {
  const 分组 = 展开IPv6(地址);
  if (!分组) return true; // 看不懂的地址，一律当作内网处理
  const 内嵌IPv4 = () => 是内网IPv4([分组[6] >> 8, 分组[6] & 255, 分组[7] >> 8, 分组[7] & 255]);
  if (分组.slice(0, 6).every((数) => 数 === 0)) return true; // ::/96：未指定地址、回环地址 ::1、旧式 IPv4 兼容地址
  if (分组.slice(0, 5).every((数) => 数 === 0) && 分组[5] === 0xffff) return 内嵌IPv4(); // ::ffff:a.b.c.d（IPv4 映射地址）
  if (分组[0] === 0x64 && 分组[1] === 0xff9b && 分组.slice(2, 6).every((数) => 数 === 0)) return 内嵌IPv4(); // 64:ff9b::/96（NAT64）
  if ((分组[0] & 0xfe00) === 0xfc00) return true; // fc00::/7（包括 Railway 的 fd12:: 内部网络）
  if ((分组[0] & 0xffc0) === 0xfe80) return true; // fe80::/10
  return (分组[0] & 0xff00) === 0xff00; // 组播
}

function 是内网地址(ip) {
  if (net.isIPv4(ip)) return 是内网IPv4(ip.split(".").map(Number));
  if (net.isIPv6(ip)) return 是内网IPv6(ip);
  return true;
}

function 禁止的域名(主机) {
  const 名称 = 主机.toLowerCase().replace(/\.$/, "");
  return (
    名称 === "localhost" ||
    名称.endsWith(".localhost") ||
    名称.endsWith(".local") ||
    名称.endsWith(".internal") ||
    名称.endsWith(".localdomain")
  );
}

// 自己解析目标域名，只返回允许连接的地址。
// 连接的是校验过的地址（而不是域名），这样也堵住了 DNS 重绑定的漏洞。
async function 解析允许地址(主机) {
  if (net.isIP(主机)) {
    if (!允许内网 && 是内网地址(主机)) return { 错误: 2 };
    return { 地址: 主机, 协议族: net.isIPv6(主机) ? 6 : 4 };
  }
  if (!允许内网 && 禁止的域名(主机)) return { 错误: 2 };
  let 记录;
  try {
    记录 = await Promise.race([
      dns.promises.lookup(主机, { all: true, verbatim: true }),
      延迟(解析超时毫秒).then(() => {
        throw Object.assign(new Error("域名解析超时"), { code: "ETIMEDOUT" });
      }),
    ]);
  } catch (异常) {
    return { 错误: 异常 && 异常.code === "ETIMEDOUT" ? 6 : 4 };
  }
  const 可用 = 记录.filter((项) => 允许内网 || !是内网地址(项.address));
  if (!可用.length) return { 错误: 2 };
  可用.sort((甲, 乙) => 甲.family - 乙.family); // 先用 IPv4：很多主机没有 IPv6 出口
  return { 地址: 可用[0].address, 协议族: 可用[0].family };
}

function 应答码(异常) {
  switch (异常 && 异常.code) {
    case "ECONNREFUSED":
      return 5;
    case "ETIMEDOUT":
      return 6;
    case "ENETUNREACH":
      return 3;
    case "EHOSTUNREACH":
    case "ENOTFOUND":
    case "EAI_AGAIN":
      return 4;
    default:
      return 1;
  }
}

const 应答 = (码) => Buffer.from([5, 码, 0, 1, 0, 0, 0, 0, 0, 0]);

// 带一个常驻监听器的缓冲读取器（两次读取之间不会漏掉任何数据）。
class 字节读取器 {
  constructor(套接字) {
    this.套接字 = 套接字;
    this.缓冲 = Buffer.alloc(0);
    this.等待中 = null;
    this.已关闭 = false;
    this.收到数据 = (数据块) => {
      this.缓冲 = Buffer.concat([this.缓冲, 数据块]);
      if (this.缓冲.length > 4096 && this.等待中 === null) {
        this.已关闭 = true;
        套接字.destroy();
      }
      this.刷新();
    };
    this.已结束 = () => {
      this.已关闭 = true;
      this.刷新();
    };
    套接字.on("data", this.收到数据);
    套接字.on("end", this.已结束);
    套接字.on("close", this.已结束);
    套接字.on("error", this.已结束);
  }
  刷新() {
    if (!this.等待中) return;
    const { 长度, 成功, 失败 } = this.等待中;
    if (this.缓冲.length >= 长度) {
      const 结果 = this.缓冲.subarray(0, 长度);
      this.缓冲 = this.缓冲.subarray(长度);
      this.等待中 = null;
      成功(结果);
    } else if (this.已关闭) {
      this.等待中 = null;
      失败(new Error("客户端已关闭"));
    }
  }
  读取(长度) {
    return new Promise((成功, 失败) => {
      this.等待中 = { 长度, 成功, 失败 };
      this.刷新();
    });
  }
  // 停止读取，并把已经收到的数据交还给调用方。
  分离() {
    this.套接字.off("data", this.收到数据);
    this.套接字.off("end", this.已结束);
    this.套接字.off("close", this.已结束);
    this.套接字.off("error", this.已结束);
    this.套接字.pause();
    const 剩余 = this.缓冲;
    this.缓冲 = Buffer.alloc(0);
    return 剩余;
  }
}

// ---------------------------------------------------------------- 连接处理

let 近期认证失败 = 0;
setInterval(() => {
  近期认证失败 = 0;
}, 60000).unref();

async function 处理连接(客户端) {
  客户端.on("error", () => {});
  客户端.setNoDelay(true);
  const 读取器 = new 字节读取器(客户端);
  const 握手定时器 = setTimeout(() => 客户端.destroy(), 握手超时毫秒);

  try {
    let 头 = await 读取器.读取(2);
    if (头[0] !== 5) {
      客户端.destroy();
      return;
    }
    const 方法列表 = Array.from(await 读取器.读取(头[1]));

    if (需要认证) {
      if (!方法列表.includes(2)) {
        客户端.end(Buffer.from([5, 0xff]));
        return;
      }
      客户端.write(Buffer.from([5, 2]));

      头 = await 读取器.读取(2);
      if (头[0] !== 1) {
        客户端.destroy();
        return;
      }
      const 收到的用户名 = (await 读取器.读取(头[1])).toString("utf8");
      const 密码长度 = (await 读取器.读取(1))[0];
      const 收到的密码 = (await 读取器.读取(密码长度)).toString("utf8");

      const 通过 = 安全比较(收到的用户名, 用户名) && 安全比较(收到的密码, 密码);
      if (!通过) {
        近期认证失败++;
        clearTimeout(握手定时器); // 下面的延迟有上限（最多 5 秒），不能被握手超时截断
        // 拖慢猜测的速度；失败不断出现时，延迟会越来越长
        await 延迟(1000 + Math.min(近期认证失败 * 100, 4000));
        客户端.end(Buffer.from([1, 1]));
        return;
      }
      客户端.write(Buffer.from([1, 0]));
    } else {
      if (!方法列表.includes(0)) {
        客户端.end(Buffer.from([5, 0xff]));
        return;
      }
      客户端.write(Buffer.from([5, 0]));
    }

    const 请求 = await 读取器.读取(4);
    if (请求[0] !== 5 || 请求[1] !== 1) {
      客户端.end(应答(7));
      return;
    }
    const 地址类型 = 请求[3];
    let 主机;
    if (地址类型 === 1) {
      主机 = Array.from(await 读取器.读取(4)).join(".");
    } else if (地址类型 === 4) {
      const 原始 = await 读取器.读取(16);
      const 各段 = [];
      for (let i = 0; i < 16; i += 2) 各段.push(原始.readUInt16BE(i).toString(16));
      主机 = 各段.join(":");
    } else if (地址类型 === 3) {
      const 长度 = (await 读取器.读取(1))[0];
      主机 = (await 读取器.读取(长度)).toString("utf8");
    } else {
      客户端.end(应答(8));
      return;
    }
    const 端口 = (await 读取器.读取(2)).readUInt16BE(0);
    clearTimeout(握手定时器);

    if (!主机 || 屏蔽端口.has(端口)) {
      客户端.end(应答(2));
      return;
    }
    const 目标 = await 解析允许地址(主机);
    if (目标.错误) {
      客户端.end(应答(目标.错误));
      return;
    }

    const 剩余数据 = 读取器.分离();
    const 上游 = net.connect({ host: 目标.地址, port: 端口, family: 目标.协议族 });
    上游.setNoDelay(true);
    上游.setTimeout(连接超时毫秒);

    let 已连接 = false;
    const 全部关闭 = () => {
      客户端.destroy();
      上游.destroy();
    };
    上游.on("error", (异常) => {
      if (!已连接 && !客户端.destroyed) 客户端.end(应答(应答码(异常)));
      全部关闭();
    });
    上游.on("timeout", () => {
      if (!已连接 && !客户端.destroyed) 客户端.end(应答(6));
      全部关闭();
    });
    上游.on("close", 全部关闭);
    客户端.on("close", 全部关闭);

    上游.on("connect", () => {
      已连接 = true;
      上游.setTimeout(空闲超时毫秒);
      客户端.setTimeout(空闲超时毫秒);
      客户端.on("timeout", 全部关闭);
      客户端.write(应答(0));
      if (剩余数据.length) 上游.write(剩余数据);
      客户端.pipe(上游);
      上游.pipe(客户端);
      客户端.resume();
    });
  } catch {
    clearTimeout(握手定时器);
    客户端.destroy();
  }
}

// ---------------------------------------------------------------- 服务器

const 服务器 = net.createServer(处理连接);
服务器.maxConnections = 最大连接数;
服务器.on("error", (异常) => {
  console.error(`服务器错误：${异常 && 异常.message}`);
  process.exit(1);
});
服务器.listen(监听端口, () => {
  if (!需要认证) console.log("警告：ALLOW_OPEN=1，中继正在没有认证的状态下运行");
  console.log(`socks5 中继已在端口 ${监听端口} 上监听`);
});

// 容器被替换时，Railway 会发送 SIGTERM。
function 关闭服务() {
  服务器.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 5000).unref();
}
process.on("SIGTERM", 关闭服务);
process.on("SIGINT", 关闭服务);

// 单个有问题的连接，绝不能让整个中继挂掉。
process.on("uncaughtException", (异常) => console.error(`未捕获的异常：${异常 && 异常.message}`));
process.on("unhandledRejection", (异常) => console.error(`未处理的拒绝：${异常 && 异常.message}`));
