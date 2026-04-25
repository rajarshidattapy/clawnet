# Telegram Integration Setup Guide

## Status: READY FOR CONFIGURATION

Your ClawNet Telegram bot is **structurally sound** but needs configuration. Here's what was fixed:

---

## ✅ What Was Fixed

### Code Improvements (telegram_alert.py)
1. **Added Retry Logic** - Failed sends now retry with exponential backoff (1s, 2s, 4s)
2. **Better Error Handling** - Distinguishes transient errors (network) from permanent errors (bad config)
3. **Fixed Race Condition** - Chat ID persisted before setting ready flag
4. **Added Startup Validation** - Clear warning if TELEGRAM_CHAT_ID is missing
5. **Thread-Safe Ready Property** - All state changes protected by mutex

### API Compliance
✅ Implementation matches **Telegram Bot API spec** for `sendMessage`:
- `chat_id` (required) ✓
- `text` (required) ✓  
- `parse_mode="HTML"` (optional) ✓

---

## 🚨 CRITICAL: Get Your Chat ID

**This is the only thing blocking message delivery.**

### Method 1: @userinfobot (Recommended - 30 seconds)
1. Open Telegram and search for **@userinfobot**
2. Send the `/start` command
3. Bot responds: `Id: 1234567890` ← Copy this number

### Method 2: Run test_telegram.py
```bash
cd c:\Users\asus\Desktop\clawnet
python test_telegram.py
```
The script will:
- Verify your bot token is valid
- Send a test message
- Capture your chat ID automatically
- Update `.env` file

---

## 📝 Update Your .env File

Add this line to `c:\Users\asus\Desktop\clawnet\.env`:

```env
OPENAI_API_KEY=sk-proj-...
TELEGRAM_BOT_TOKEN=8739324470:AAEkfja_OaCetvzI4ENwYeECiwKp3FKbd48
TELEGRAM_CHAT_ID=1234567890
SUPERMEMORY_API_KEY=sm_...
TELEGRAM_MOCK_ENABLED=1
```

**Replace `1234567890` with your actual Chat ID**

---

## ✔️ Verification Checklist

After adding `TELEGRAM_CHAT_ID`:

1. **Start ClawNet:**
   ```bash
   python clawnet.py
   ```

2. **Send Test Alert:**
   - ClawNet monitors network → detects threat → sends Telegram alert
   - You should receive message on Telegram within seconds

3. **Check Status in Telegram:**
   - Send `/status` to bot
   - Should show: "✅ No pending actions" or list pending items

4. **Test Remote Command:**
   - Alert includes `/approve` or `/deny` buttons
   - Try approving an action via Telegram

---

## 🔧 Troubleshooting

### Bot Status Shows "warning: TELEGRAM_CHAT_ID not set"
- [ ] Ensure `.env` file has `TELEGRAM_CHAT_ID=1234567890` line
- [ ] No spaces around `=` sign
- [ ] Number contains only digits (no @ symbol)
- [ ] Restart ClawNet after editing `.env`

### "send-error: bad-config"
- [ ] Chat ID is invalid (wrong number)
- [ ] Double-check with @userinfobot

### "send-error" with network message
- [ ] Temporary Telegram API outage
- [ ] Bot automatically retries (3 attempts with 1s, 2s, 4s delays)
- [ ] Check internet connection

### Bot doesn't respond to /start
- [ ] Telegram bot not running (check task manager)
- [ ] Bot token invalid
- [ ] Re-add bot token to `.env` from @BotFather

---

## 📊 How to Monitor

Check bot status in ClawNet output:
- `initializing…` → Bot starting up
- `warning: TELEGRAM_CHAT_ID not set` → **ADD CHAT ID**
- `connected` → Ready to send alerts ✅
- `send-error: {error}` → See troubleshooting above

---

## 🎯 Expected Flow

1. ✅ Add `TELEGRAM_CHAT_ID` to `.env`
2. ✅ Restart ClawNet
3. ✅ Status shows "connected"
4. ✅ Threat detected → Alert sent to Telegram
5. ✅ User responds with `/approve` or `/deny`
6. ✅ ClawNet executes action

---

**Need help?** Check ClawNet logs for exact error messages.
