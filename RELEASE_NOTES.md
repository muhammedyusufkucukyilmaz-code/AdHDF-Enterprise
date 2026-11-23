# AdHDF Enterprise v2.0.2 — Standalone Executable Release

Bu sürüm, **AdHDF Enterprise** uygulamasının derlenmiş masaüstü dağıtımıdır.

## Doğrulama ve Kurulum
1. AdHDF_Enterprise.exe dosyasını ayrı bir klasöre indirin ve SHA-256 değerini doğrulayın:
   - **SHA-256:** `82C259D2D5FD6A93BC3BBCB023193F87EA8763D1D15D14D4DF2F76C074BE1834`
2. Uygulamayı **Yönetici olarak çalıştırın** ve ilk kurulum sihirbazı üzerinden kendi **SOC Kullanıcı Adı ve Parolanızı** oluşturun.
3. Kendi **port** (APP_PORT veya otomatik boş port), **IP / ağ / Cloudflare Tunnel** (CALLBACK_HOST), **webhook / eşik** (WEBHOOK_URL, BLOCK_THRESHOLD, BAN_TTL_HOURS) ve **AI motoru** (**AI-Free Mode** veya **Auto-Detect AI** ile yerel Ollama / LM Studio / özel port) ayarlarınızı kendinize özel şekilde yapılandırabilirsiniz.

## Sık Karşılaşılan Durumlar ve Sorun Giderme
* **İlk Kurulum Ekranı Gelmiyor:** Çalıştırdığınız klasörde önceden oluşturulmuş bir .env veya SETUP_COMPLETED=true ayarı olabilir. Temiz bir klasörde .env olmadan başlatın.
* **Kullanıcı Adı / Şifre İstiyor:** Kurulum tamamlandıktan sonra /soc/dashboard erişimi kendi belirlediğiniz SOC kimlik bilgileriyle korunur; şifrenizi unutursanız çalışma dizinindeki .env içindeki SOC_USERNAME ve SOC_PASSWORD değerlerini kontrol edebilirsiniz.
* **Cloudflare Tunnel Başlamıyor:** Sistemde cloudflared.exe kurulu değilse tünel başlatılamaz; gerekirse winget install Cloudflare.cloudflared ile kurabilir veya yerel modda çalışmaya devam edebilirsiniz.
* **Yerel AI Bağlanamıyor:** Ollama veya LM Studio servisinin açık olduğunu doğrulayın, farklı bir port kullanıyorsanız http://127.0.0.1:<port>/v1 adresini girip test edin ya da **AI-Free Mode** seçin.
* **Port Çakışması:** Seçili port meşgulse sistem boş port seçer; sabit port için .env dosyasında APP_PORT değerini güncelleyip uygulamayı yeniden başlatın.

## Telif Hakkı ve Kullanım Koşulları
Copyright (c) 2026 **Muhammed Yusuf Küçükyılmaz**. Tüm hakları saklıdır.
Kaynak kodlar özel depoda tutulmakta olup gizlidir; izinsiz kopyalama, tersine mühendislik, yeniden dağıtım veya ticari kullanım yasaktır.
