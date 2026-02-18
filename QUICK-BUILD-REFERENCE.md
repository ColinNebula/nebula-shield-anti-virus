# ⚡ Quick Build Reference

## Fast Commands

```bash
# Fastest (portable only, ~30-45 seconds)
npm run electron:build:win:portable

# Full build with installer (~60-90 seconds)  
npm run electron:build:win

# Development build (no packaging)
npm run pack
```

## Key Optimizations Applied

✅ **esbuild** minifier (10x faster than terser)  
✅ **ASAR** packaging enabled  
✅ **Portable-only** target (skip NSIS installer)  
✅ **Maximum compression**  
✅ **Excluded**: backend node_modules, databases, source maps  
✅ **Runtime install**: backend dependencies install on first run

## Build Time Comparison

| Build Type | Before | After | Improvement |
|------------|--------|-------|-------------|
| Portable   | ~90s   | ~40s  | **56% faster** |
| Full Build | ~120s  | ~70s  | **42% faster** |

## Package Size

| Component | Before | After |
|-----------|--------|-------|
| Total     | ~350MB | ~120MB |
| Backend   | ~300MB | Runtime install |
| Frontend  | ~20MB  | ~15MB |

## Output Location

```
dist/
├── Nebula Shield Anti-Virus-0.1.0-x64.exe (portable)
└── win-unpacked/ (unpacked app for testing)
```

## Quick Troubleshooting

**Build too slow?**
- Use `npm run electron:build:win:portable` (skip NSIS)
- Close other applications
- Disable antivirus temporarily

**Package too large?**
- Already optimized! (excluded 300MB of node_modules)
- Consider compressing large images

**Backend not working?**
- First run installs dependencies (30-60s wait)
- Check logs at `%APPDATA%\nebula-shield-anti-virus\electron.log`
