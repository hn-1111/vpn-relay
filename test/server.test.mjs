// 中继的行为测试：启动真正的 server.js，用 SOCKS5 协议逐项验证。
// 运行：npm test（等同于 node --test test/*.test.mjs）

import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const 服务文件 = join(dirname(fileURLToPath(import.meta.url)), "..", "server.js");
const 用户 = "user1";
const 密码 = "pass1";

function 空闲端口() {
  return new Promise((完成) => {
    const 临时 = net.createServer();
    临时.listen(0, "127.0.0.1", () => {
      const { port } = 临时.address();
      临时.close(() => 完成(port));
    });
  });
}

// 本机上的回显服务，供中继去连接
async function 启动回显() {
  const 服务 = net.createServer((套接字) => {
    套接字.on("error", () => {});
    套接字.on("data", (数据) => 套接字.write(数据));
  });
  await new Promise((完成) => 服务.listen(0, "127.0.0.1", 完成));
  return { 端口: 服务.address().port, 关闭: () => 服务.close() };
}

// 启动中继，等它开始接受连接；环境变量不对时返回它的退出码
async function 启动中继(环境 = {}) {
  const 端口 = await 空闲端口();
  const 子进程 = spawn(process.execPath, [服务文件], {
    env: { PATH: process.env.PATH, SOCKS_PORT: String(端口), ...环境 },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let 输出 = "";
  子进程.stdout.on("data", (数据) => (输出 += 数据));
  子进程.stderr.on("data", (数据) => (输出 += 数据));
  const 退出 = new Promise((完成) => 子进程.on("exit", (代码) => 完成(代码)));
  const 已启动 = await Promise.race([
    (async () => {
      for (let 次 = 0; 次 < 100; 次++) {
        const 可连 = await new Promise((完成) => {
          const 探测 = net.connect(端口, "127.0.0.1");
          探测.on("connect", () => {
            探测.destroy();
            完成(true);
          });
          探测.on("error", () => 完成(false));
        });
        if (可连) return true;
        await new Promise((完成) => setTimeout(完成, 50));
      }
      return false;
    })(),
    退出.then(() => false),
  ]);
  return { 端口, 已启动, 退出, 输出: () => 输出, 停止: () => 子进程.kill("SIGKILL"), 温和停止: () => 子进程.kill("SIGTERM") };
}

const 拼接 = (...各部分) => Buffer.concat(各部分.map((部分) => (Buffer.isBuffer(部分) ? 部分 : Buffer.from(部分))));
const 问候 = (...方法) => 拼接([5, 方法.length, ...方法]);
// 长度字段是字节数（不是字符数），账号密码里有中文时两者不同
const 认证 = (名, 口令) => {
  const 名字节 = Buffer.from(名);
  const 口令字节 = Buffer.from(口令);
  return 拼接([1, 名字节.length], 名字节, [口令字节.length], 口令字节);
};
const 连接IPv4 = (主机, 端口) => 拼接([5, 1, 0, 1, ...主机.split(".").map(Number), 端口 >> 8, 端口 & 255]);
const 连接域名 = (名称, 端口) => 拼接([5, 1, 0, 3, 名称.length], Buffer.from(名称), [端口 >> 8, 端口 & 255]);
const 连接IPv6 = (十六字节, 端口) => 拼接([5, 1, 0, 4, ...十六字节, 端口 >> 8, 端口 & 255]);
const 登录 = () => [问候(0, 2), 认证(用户, 密码)];

// 依次发送各步骤，返回收到的每段应答（十六进制）和连接的结局
function 对话(端口, 步骤, 空闲毫秒 = 600) {
  return new Promise((完成) => {
    const 套接字 = net.connect(端口, "127.0.0.1");
    const 应答 = [];
    let 序号 = 0;
    let 定时器 = null;
    const 结束 = (结局) => {
      clearTimeout(定时器);
      套接字.destroy();
      完成({ 应答, 结局 });
    };
    const 下一步 = () => {
      clearTimeout(定时器);
      if (序号 < 步骤.length) {
        套接字.write(步骤[序号++]);
        定时器 = setTimeout(下一步, 空闲毫秒);
      } else {
        定时器 = setTimeout(() => 结束("空闲"), 空闲毫秒);
      }
    };
    套接字.on("connect", 下一步);
    套接字.on("data", (数据) => {
      应答.push(数据.toString("hex"));
      clearTimeout(定时器);
      定时器 = setTimeout(下一步, 60);
    });
    套接字.on("close", () => 结束("已关闭"));
    套接字.on("error", () => 结束("出错"));
    setTimeout(() => 结束("超时"), 8000);
  });
}

// SOCKS5 应答的状态码：05 <码> 00 01 ...
const 状态码 = (十六进制) => (十六进制 ? parseInt(十六进制.slice(2, 4), 16) : null);

async function 带中继(环境, 测试) {
  const 回显 = await 启动回显();
  const 中继 = await 启动中继(环境);
  try {
    assert.ok(中继.已启动, `中继没有启动：${中继.输出()}`);
    await 测试({ 中继, 回显 });
  } finally {
    中继.停止();
    回显.关闭();
  }
}

const 允许本机 = { SOCKS_USER: 用户, SOCKS_PASS: 密码, ALLOW_PRIVATE_DESTINATIONS: "1" };
const 默认设置 = { SOCKS_USER: 用户, SOCKS_PASS: 密码 };

test("账号密码正确：可以通过中继连到目标，数据原样往返", () =>
  带中继(允许本机, async ({ 中继, 回显 }) => {
    const 结果 = await 对话(中继.端口, [...登录(), 连接IPv4("127.0.0.1", 回显.端口), Buffer.from("你好，中继")]);
    assert.deepEqual(结果.应答.slice(0, 3), ["0502", "0100", "05000001000000000000"]);
    assert.equal(Buffer.from(结果.应答[3], "hex").toString("utf8"), "你好，中继");
  }));

test("所有数据一次发出（握手和数据粘在一起）也能正常转发", () =>
  带中继(允许本机, async ({ 中继, 回显 }) => {
    const 结果 = await 对话(中继.端口, [拼接(问候(0, 2), 认证(用户, 密码), 连接IPv4("127.0.0.1", 回显.端口), "粘包数据")]);
    // 应答可能被合并成一段，所以拼在一起再看
    assert.equal(结果.应答.join(""), "0502" + "0100" + "05000001000000000000" + Buffer.from("粘包数据").toString("hex"));
  }));

test("账号密码里有中文也能登录（按 UTF-8 字节比较）", () =>
  带中继({ SOCKS_USER: "用户甲", SOCKS_PASS: "口令乙", ALLOW_PRIVATE_DESTINATIONS: "1" }, async ({ 中继, 回显 }) => {
    const 通过 = await 对话(中继.端口, [问候(0, 2), 认证("用户甲", "口令乙"), 连接IPv4("127.0.0.1", 回显.端口), "ok"]);
    assert.equal(通过.应答.slice(0, 3).join(""), "0502" + "0100" + "05000001000000000000");
    const 失败 = await 对话(中继.端口, [问候(0, 2), 认证("用户甲", "口令丙")], 1700);
    assert.deepEqual(失败.应答, ["0502", "0101"]);
  }));

test("密码错误、用户名错误：被拒绝并断开", () =>
  带中继(允许本机, async ({ 中继 }) => {
    for (const [名, 口令] of [[用户, "错的"], ["别人", 密码]]) {
      const 结果 = await 对话(中继.端口, [问候(0, 2), 认证(名, 口令)], 1700);
      assert.deepEqual(结果.应答, ["0502", "0101"]);
      assert.equal(结果.结局, "已关闭");
    }
  }));

test("客户端只提供“无认证”方式：被拒绝（05 ff）", () =>
  带中继(默认设置, async ({ 中继 }) => {
    const 结果 = await 对话(中继.端口, [问候(0)]);
    assert.deepEqual(结果.应答, ["05ff"]);
  }));

test("没有设置账号密码就拒绝启动；设置 ALLOW_OPEN=1 才作为开放代理启动", async () => {
  const 拒绝 = await 启动中继({});
  assert.equal(await 拒绝.退出, 1);
  assert.match(拒绝.输出(), /SOCKS_USER/);

  const 开放 = await 启动中继({ ALLOW_OPEN: "1", ALLOW_PRIVATE_DESTINATIONS: "1" });
  const 回显 = await 启动回显();
  try {
    assert.ok(开放.已启动, 开放.输出());
    const 结果 = await 对话(开放.端口, [问候(0), 连接IPv4("127.0.0.1", 回显.端口), "开放"]);
    assert.equal(结果.应答[0], "0500");
    assert.equal(Buffer.from(结果.应答[2], "hex").toString(), "开放");
  } finally {
    开放.停止();
    回显.关闭();
  }
});

test("默认屏蔽的端口（25、3389 ……）被拒绝；BLOCKED_PORTS 可以改写这份名单", async () => {
  await 带中继(允许本机, async ({ 中继 }) => {
    for (const 端口 of [25, 445, 3389]) {
      const 结果 = await 对话(中继.端口, [...登录(), 连接IPv4("127.0.0.1", 端口)]);
      assert.equal(状态码(结果.应答[2]), 2, `端口 ${端口}`);
    }
  });
  await 带中继({ ...允许本机, BLOCKED_PORTS: "none" }, async ({ 中继 }) => {
    const 结果 = await 对话(中继.端口, [...登录(), 连接IPv4("127.0.0.1", 25)]);
    assert.equal(状态码(结果.应答[2]), 5, "不再屏蔽：这次是目标自己拒绝了连接");
  });
  await 带中继({ ...允许本机, BLOCKED_PORTS: "9, abc, 70000, 8081" }, async ({ 中继 }) => {
    assert.equal(状态码((await 对话(中继.端口, [...登录(), 连接IPv4("127.0.0.1", 9)])).应答[2]), 2);
    assert.equal(状态码((await 对话(中继.端口, [...登录(), 连接IPv4("127.0.0.1", 8081)])).应答[2]), 2);
    assert.equal(状态码((await 对话(中继.端口, [...登录(), 连接IPv4("127.0.0.1", 25)])).应答[2]), 5);
  });
});

test("目标是内网 / 回环 / 元数据地址时一律拒绝（各种 IPv4、域名、IPv6 写法）", () =>
  带中继(默认设置, async ({ 中继 }) => {
    const 八位 = (...字节) => 字节;
    const 映射 = (a, b, c, d) => 八位(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d);
    const 各项 = [
      ["回环 127.0.0.1", 连接IPv4("127.0.0.1", 80)],
      ["10.x", 连接IPv4("10.1.2.3", 80)],
      ["172.16.x", 连接IPv4("172.16.5.5", 80)],
      ["192.168.x", 连接IPv4("192.168.5.5", 80)],
      ["云平台元数据 169.254.169.254", 连接IPv4("169.254.169.254", 80)],
      ["运营商级 NAT / Railway 内部 100.64.x", 连接IPv4("100.64.0.1", 80)],
      ["组播 224.x", 连接IPv4("224.0.0.1", 80)],
      ["域名 localhost", 连接域名("localhost", 80)],
      ["域名 db.internal", 连接域名("db.internal", 80)],
      ["域名 printer.local", 连接域名("printer.local", 80)],
      ["域名 x.localdomain.（带结尾的点）", 连接域名("x.localdomain.", 80)],
      ["IPv6 ::1（16 个原始字节）", 连接IPv6(八位(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1), 80)],
      ["IPv6 ::1（文本，完整写法）", 连接域名("0:0:0:0:0:0:0:1", 80)],
      ["IPv6 ::1（文本，压缩写法）", 连接域名("::1", 80)],
      ["IPv4 映射 ::ffff:127.0.0.1", 连接IPv6(映射(127, 0, 0, 1), 80)],
      ["IPv4 映射 ::ffff:10.0.0.1", 连接IPv6(映射(10, 0, 0, 1), 80)],
      ["IPv4 映射 ::ffff:100.64.0.1", 连接IPv6(映射(100, 64, 0, 1), 80)],
      ["IPv4 映射 ::ffff:169.254.169.254", 连接IPv6(映射(169, 254, 169, 254), 80)],
      ["IPv4 映射（文本）::ffff:127.0.0.1", 连接域名("::ffff:127.0.0.1", 80)],
      ["旧式 IPv4 兼容 ::7f00:1", 连接IPv6(八位(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x7f, 0, 0, 1), 80)],
      ["NAT64 64:ff9b::7f00:1", 连接IPv6(八位(0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0x7f, 0, 0, 1), 80)],
      ["IPv6 内部网络 fd12::1", 连接IPv6(八位(0xfd, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1), 80)],
      ["IPv6 fc00::1", 连接IPv6(八位(0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1), 80)],
      ["IPv6 链路本地 fe80::1", 连接IPv6(八位(0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1), 80)],
      ["IPv6 组播 ff02::1", 连接IPv6(八位(0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1), 80)],
    ];
    for (const [名称, 请求] of 各项) {
      const 结果 = await 对话(中继.端口, [...登录(), 请求], 400);
      assert.equal(状态码(结果.应答[2]), 2, `${名称} 应当被拒绝（应答：${结果.应答.join(" ")}）`);
    }
  }));

test("公网地址不会被误当成内网（IPv6、IPv4 映射的公网地址：不能被拒绝）", () =>
  带中继({ ...默认设置, CONNECT_TIMEOUT_MS: "1200" }, async ({ 中继 }) => {
    const 各项 = [
      ["公网 IPv6 2001:4860:4860::8888", 连接IPv6([0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88], 80)],
      ["IPv4 映射的公网地址 ::ffff:8.8.8.8", 连接IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8], 80)],
    ];
    for (const [名称, 请求] of 各项) {
      const 结果 = await 对话(中继.端口, [...登录(), 请求], 2500);
      const 码 = 状态码(结果.应答[2]);
      assert.notEqual(码, 2, `${名称}：不应被当作内网拒绝`);
      assert.notEqual(码, null, `${名称}：应当收到应答（${结果.结局}）`);
    }
  }));

test("连接失败时给出对应的状态码：目标拒绝连接（5）、域名解析不了（4）、不支持的命令（7）、不支持的地址类型（8）", () =>
  带中继(允许本机, async ({ 中继, 回显 }) => {
    assert.equal(状态码((await 对话(中继.端口, [...登录(), 连接IPv4("127.0.0.1", 1)])).应答[2]), 5);
    assert.equal(状态码((await 对话(中继.端口, [...登录(), 连接域名("no-such-host.invalid", 80)], 1500)).应答[2]), 4);
    assert.equal(状态码((await 对话(中继.端口, [...登录(), 拼接([5, 2, 0, 1, 127, 0, 0, 1, 0, 80])])).应答[2]), 7);
    assert.equal(状态码((await 对话(中继.端口, [...登录(), 拼接([5, 1, 0, 9, 0, 0])])).应答[2]), 8);
    assert.equal(状态码((await 对话(中继.端口, [...登录(), 连接域名("", 回显.端口)])).应答[2]), 2, "空的主机名");
  }));

test("不是 SOCKS5 的连接、握手前塞满垃圾数据、握手卡住：都会被直接断开", () =>
  带中继({ ...允许本机, HANDSHAKE_TIMEOUT_MS: "400" }, async ({ 中继 }) => {
    const 旧版本 = await 对话(中继.端口, [拼接([4, 1, 0, 80, 127, 0, 0, 1, 0])]);
    assert.deepEqual(旧版本.应答, []);
    assert.equal(旧版本.结局, "已关闭");
    const 垃圾 = await 对话(中继.端口, [Buffer.alloc(5000, 0x41)]);
    assert.deepEqual(垃圾.应答, []);
    assert.equal(垃圾.结局, "已关闭");
    const 卡住 = await 对话(中继.端口, [拼接([5, 2, 0])], 1500);
    assert.equal(卡住.结局, "已关闭", "握手超时后被断开");
  }));

test("空闲的隧道会在 IDLE_TIMEOUT_MS 之后关闭", () =>
  带中继({ ...允许本机, IDLE_TIMEOUT_MS: "500" }, async ({ 中继, 回显 }) => {
    const 套接字 = net.connect(中继.端口, "127.0.0.1");
    const 已关闭 = new Promise((完成) => 套接字.on("close", () => 完成(Date.now())));
    套接字.on("error", () => {});
    套接字.resume(); // 不读取的话，对方关闭连接的消息不会被处理，close 事件也就不会出现
    套接字.write(拼接(问候(0, 2), 认证(用户, 密码), 连接IPv4("127.0.0.1", 回显.端口)));
    const 开始 = Date.now();
    const 结束 = await Promise.race([已关闭, new Promise((完成) => setTimeout(() => 完成(null), 4000))]);
    assert.ok(结束 !== null, "隧道应当被关闭");
    assert.ok(结束 - 开始 < 3500);
  }));

test("收到 SIGTERM（Railway 替换容器时发送）时正常退出，退出码 0", async () => {
  const 中继 = await 启动中继(默认设置);
  assert.ok(中继.已启动, 中继.输出());
  中继.温和停止();
  assert.equal(await 中继.退出, 0);
});

test("端口已被占用时报错退出（退出码 1）", async () => {
  const 占位 = net.createServer();
  await new Promise((完成) => 占位.listen(0, 完成)); // 和中继一样不指定地址，保证会冲突
  try {
    // 环境变量里的 SOCKS_PORT 优先，所以中继会去监听这个已被占用的端口
    const 中继 = await 启动中继({ ...默认设置, SOCKS_PORT: String(占位.address().port) });
    assert.equal(await 中继.退出, 1);
    assert.match(中继.输出(), /EADDRINUSE/);
  } finally {
    占位.close();
  }
});
