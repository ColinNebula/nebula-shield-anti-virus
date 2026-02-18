# 🧹 Disk Cleaner - Quick Reference

## 🎯 Quick Actions

| Action | Command | Result |
|--------|---------|--------|
| **Full Cleanup** | Click "Clean All" | Cleans all categories automatically |
| **Analyze Space** | Click "Re-analyze" | Scans disk for cleanable items |
| **Find Duplicates** | Duplicates tab → Scan | Finds duplicate files by hash |
| **Large Files** | Large Files tab → Scan | Finds files over 500 MB |
| **Privacy Clean** | Privacy tab → Clean Privacy | Removes browsing traces |
| **Registry Clean** | Privacy tab → Clean Registry | Fixes invalid entries |
| **View Startups** | Privacy tab → View Startups | Lists boot programs |

## 📂 Cleanup Categories

### Quick Cleanup Tab

| Category | Location | Typical Size | Safe to Clean |
|----------|----------|--------------|---------------|
| **Recycle Bin** | `$Recycle.Bin` | 100 MB - 2 GB | ✅ Yes |
| **Temp Files** | `%Temp%`, `C:\Windows\Temp` | 500 MB - 5 GB | ✅ Yes |
| **Old Downloads** | `Downloads` (30+ days) | 100 MB - 5 GB | ⚠️ Review first |
| **Thumbnails** | ThumbCache | 50 MB - 500 MB | ✅ Yes |
| **Error Reports** | WER, CrashDumps | 100 MB - 1 GB | ✅ Yes |
| **Windows.old** | `C:\Windows.old` | 5 GB - 30 GB | ⚠️ Admin required |

### Privacy & Security Tab

| Feature | Purpose | Impact |
|---------|---------|--------|
| **Privacy Cleaner** | Remove recent files, clipboard | Privacy protection |
| **Registry Cleaner** | Fix invalid registry entries | Performance boost |
| **Startup Manager** | Control boot programs | Faster startup |
| **Security Audit** | Find vulnerabilities | Security improvement |

### Optimize Tab

| Tool | Function | When to Use |
|------|----------|-------------|
| **Scheduled Cleanup** | Auto cleanup | Set and forget |
| **Defragmentation** | Optimize file placement | HDDs only (not SSDs) |
| **System Optimization** | Overall performance boost | Monthly |
| **Disk Health** | Check drive condition | Monitor regularly |

## 🔑 Keyboard Shortcuts

- `Tab` - Navigate between tabs
- `Enter` - Activate focused button
- `Esc` - Close modals
- `Ctrl+A` - Select all duplicates

## 📊 Size Reference

| Size | Examples |
|------|----------|
| **< 100 MB** | Small cleanup |
| **100 MB - 1 GB** | Moderate cleanup |
| **1 GB - 5 GB** | Significant cleanup |
| **> 5 GB** | Major space savings |

## ⚡ Performance Tips

### Best Practices
1. ✅ Run Quick Cleanup weekly
2. ✅ Scan duplicates monthly
3. ✅ Review large files quarterly
4. ✅ Clean privacy data before sharing PC
5. ✅ Check disk health regularly

### Avoid
1. ❌ Don't clean while programs are running
2. ❌ Don't delete without reviewing (for downloads)
3. ❌ Don't defragment SSDs
4. ❌ Don't clean system protected files

## 🛡️ Safety Levels

| Level | Description | Examples |
|-------|-------------|----------|
| 🟢 **Safe** | No risk | Temp files, recycle bin |
| 🟡 **Review** | Check first | Old downloads, duplicates |
| 🔴 **Caution** | Admin/backup needed | Windows.old, registry |

## 🔧 Common Issues

| Problem | Solution |
|---------|----------|
| Access denied | Run as Administrator |
| Files in use | Close applications |
| Slow scanning | Large drive - be patient |
| No space freed | Files may be protected |
| Registry errors | Requires elevated privileges |

## 📱 Status Icons

| Icon | Meaning |
|------|---------|
| 🔵 Spinner | Analyzing/Cleaning |
| ✅ Checkmark | Success |
| ❌ X | Error |
| ⚠️ Warning | Caution needed |
| ℹ️ Info | Information |

## 🎨 Color Codes

| Color | Category | Risk Level |
|-------|----------|------------|
| 🔴 Red | Recycle Bin, Privacy | Low risk |
| 🟠 Orange | Temp Files, Errors | Low risk |
| 🔵 Blue | Downloads | Medium risk |
| 🟣 Purple | Registry, Windows.old | High risk |
| 🟢 Green | Success state | - |

## 📈 Expected Results

### After Quick Cleanup
- **Space Freed**: 500 MB - 10 GB
- **Files Deleted**: 50 - 1000+
- **Time**: 30 seconds - 2 minutes

### After Duplicate Scan
- **Space Saved**: Varies widely
- **Time**: 2 - 10 minutes
- **Groups Found**: 10 - 100+

### After Registry Clean
- **Entries Fixed**: 50 - 500
- **Performance**: 5-10% improvement
- **Time**: 30 seconds - 1 minute

## 🔄 Update Frequency

| Task | Frequency |
|------|-----------|
| Quick Cleanup | Weekly |
| Duplicate Scan | Monthly |
| Registry Clean | Monthly |
| Privacy Clean | Before sharing/selling PC |
| Disk Health | Quarterly |
| Startup Review | Semi-annually |

## 💡 Pro Tips

1. **Before Cleanup**: Close all applications
2. **Large Files**: Sort by age and size
3. **Duplicates**: Keep original, delete copies
4. **Startup**: Disable unknown programs
5. **Privacy**: Clean before screenshots
6. **Registry**: Backup before cleaning
7. **Schedule**: Set automatic weekly cleanup
8. **Monitor**: Check disk health monthly

## 🆘 Emergency Actions

### System Running Slow
1. Quick Cleanup → Clean All
2. Check large files
3. Disable unnecessary startups
4. Clean registry

### Almost Out of Space
1. Empty Recycle Bin
2. Clean temp files
3. Find large files
4. Scan for duplicates
5. Remove Windows.old

### Privacy Concern
1. Privacy → Clean Privacy Data
2. Empty Recycle Bin permanently
3. Clear browser cache
4. Review recent files

## 📞 Quick Help

**Can't find something?**
- Check the full documentation: `DISK_CLEANER_ENHANCEMENT_GUIDE.md`

**Need more space?**
- Try all cleanup options + duplicates + large files

**Worried about deleting?**
- Review items before cleaning
- Backup important data first
- Start with "Safe" categories

---

**Version**: 2.0  
**Last Updated**: November 2025  
**Author**: Nebula Shield Development Team
