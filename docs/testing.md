# 运行测试

在项目根目录使用 Go 1.25 或更新版本运行单元测试，生成语句覆盖率报告。

```sh
go test -short -count=1 -coverpkg=peertty/... -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

末行 `total: (statements)` 是单元测试执行的语句占当前平台全部 Go 包语句的比例。用 `go tool cover -html=coverage.out` 可以逐文件查看哪些语句已执行。

目标是 **macOS 单元测试语句覆盖率超过 95%**。比较前后使用相同的 `-short`、`-coverpkg` 和平台，不为达标剔除生产文件或把全量集成测试计入单测成绩。Linux 和 Windows 有不同的平台代码，分别报告，不互相替代。

覆盖提升优先验证有行为价值的分支：授权后台进程的启动、失败与收尾；OpenSSH 检查与回收；交互界面的取消、异常输入和重试。单测使用本地替身，不改系统 SSH、防火墙或剪贴板；需要真实系统服务或双机网络的场景保留在全量测试或实验验证中。

README 徽章采用 macOS 的单元测试结果。各平台编译的 SSH、文件锁和终端实现有所不同。GitHub Actions 在 macOS、Linux 和 Windows 上运行全量测试，三端通过后更新 `main` 的徽章。在 macOS 本机运行上述命令后，也可用 Python 3 从同一份报告更新徽章。

```sh
python3 scripts/coverage_badge.py coverage.out
```

运行 `go test ./...` 同时验证原生 SSH 子进程、后台授权和两端连接。用 `go vet ./...` 做静态检查，`go test -race ./...` 检查竞态。真实双机网络和原生安装包的验证另有记录。[测试工作流](../.github/workflows/test.yml) · [双机网络实验](../lab/README.md) · [多终端授权验证](verification-2026-11-21.md) · [早期版本验证](verification-2026-11-20.md)
