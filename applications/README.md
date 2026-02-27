# oneOS Built-in Applications (Source Layer)

本目录用于存放 oneOS 系统自带应用的“源码/包描述层”，不属于 `kernel/`。

目标语义（v1）：
- `Applications` Workspace：只保存 `name -> App:<name>` 的注册关系（registry）
- 每个应用一个独立 Workspace：`App:<name>`（包 Workspace）
  - 包内对象：`AppManifest` / `AppConfig` / `AppBinary`
- `app run <name>` 必须从对应的 `App:<name>` Workspace 读取 manifest/config 后启动
- 不引入路径/目录语义（这里的目录仅是仓库源码组织方式）

说明：
- oneOS 仅支持 Rust 编写的应用：构建期产出 ELF 二进制写入 GOES 的 `App:<name>` Workspace。
- `entry = "elf:v1"`，由内核在 `AppDomain` 中加载运行（不支持 `.one` 脚本）。
