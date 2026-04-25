#!/usr/bin/env python3
"""Test script to verify Telegram bot message delivery."""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "core"))

from telegram_alert import TelegramAlert

def test_telegram():
    print("=" * 70)
    print("ClawNet Telegram Message Test")
    print("=" * 70)
    
    # Check environment variables
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    
    print(f"\n[*] Checking environment variables...")
    print(f"    TELEGRAM_BOT_TOKEN: {'✓ SET' if token else '✗ NOT SET'}")
    print(f"    TELEGRAM_CHAT_ID:  {'✓ SET' if chat_id else '✗ NOT SET'}")
    
    if not token:
        print("\n[!] ERROR: TELEGRAM_BOT_TOKEN not set")
        print("    Get token from @BotFather on Telegram")
        return False
    
    if not chat_id:
        print("\n[!] ERROR: TELEGRAM_CHAT_ID not set")
        print("    Get your chat ID from @userinfobot on Telegram")
        return False
    
    # Try to import python-telegram-bot
    print(f"\n[*] Checking python-telegram-bot installation...")
    try:
        import telegram
        print(f"    ✓ python-telegram-bot v{telegram.__version__}")
    except ImportError:
        print(f"    ✗ NOT INSTALLED")
        print(f"    Install: pip install python-telegram-bot")
        return False
    
    # Initialize TelegramAlert
    print(f"\n[*] Initializing TelegramAlert...")
    tg = TelegramAlert(token, chat_id)
    
    print(f"    available: {tg.available}")
    print(f"    ready:     {tg.ready}")
    print(f"    status:    {tg.status}")
    
    if not tg.available:
        print(f"\n[!] ERROR: TelegramAlert not available")
        return False
    
    if not tg.ready:
        print(f"\n[!] ERROR: TelegramAlert not ready (missing chat_id)")
        return False
    
    # Wait for bot to initialize
    print(f"\n[*] Waiting for bot connection (3s)...")
    time.sleep(1)
    
    # Send test message
    print(f"\n[*] Sending test message...")
    test_message = (
        "🐾 <b>ClawNet Test Message</b>\n\n"
        "✓ Bot is connected and working!\n"
        f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        "This confirms Telegram integration is functional."
    )
    
    tg.send_alert(test_message)
    print(f"    Message queued for delivery")
    
    # Wait for delivery
    print(f"\n[*] Waiting for message delivery (3s)...")
    time.sleep(3)
    
    status = tg.status
    print(f"    Final status: {status}")
    
    if "error" in status.lower():
        print(f"\n[!] ERROR: {status}")
        return False
    
    print(f"\n[✓] SUCCESS: Message sent!")
    print(f"    Check your Telegram bot for the test message")
    return True

if __name__ == "__main__":
    success = test_telegram()
    sys.exit(0 if success else 1)
