# AdHDF Enterprise (Adaptive AI-Driven HoneyToken & Active Deception Framework)

**AdHDF Enterprise**, yetkisiz tarama, dosya avcılığı ve saldırı girişimlerini karşılamak, sahte/aldatıcı yanıtlar ve izleme (canary) tuzakları sunmak ve olayları SOC panelinde izlemek için geliştirilmiş bir **Active Deception & SOC Console** uygulamasıdır.

> **Telif Hakkı ve Gizlilik:** Copyright (c) 2026 **Muhammed Yusuf Küçükyılmaz**. Tüm hakları saklıdır. Kaynak kodlar özel depoda tutulmakta olup gizlidir; izinsiz kopyalama, tersine mühendislik, yeniden dağıtım veya ticari kullanım yasaktır.

---

## Bu Nedir ve Nasıl Çalışır?

1. **Tuzak ve Aldatma Katmanı:** Gelen istekleri analiz eder; .env, id_rsa, .aws/credentials, .sql, giriş/panel yolları veya SQLi/LFI/SSRF/RCE kalıpları için sahte yanıtlar ve tekil cnry_... izleme bağlantıları/anahtarları üretir.
2. **Canary Tetikleme ve Risk Puanlama:** Saldırgan tuzak bağlantısına veya izleme uç noktasına dokunduğunda olay SQLite (WAL modu) veritabanına kaydedilir, risk puanı hesaplanır ve eşik aşılırsa webhook bildirimi tetiklenebilir.
3. **Esnek Çalışma Modları (AI-Free veya Local LLM):**
   - **AI-Free Mode (static_only):** Ekran kartı veya yerel LLM sunucusu olmadan hızlı statik aldatma yanıtlarıyla çalışır.
   - **Hybrid AI (hybrid_ai):** Yerel OpenAI uyumlu sunucularla (**Ollama**, **LM Studio** veya yerel/özel porttaki modeller) çalışır; model yanıt vermezse otomatik olarak statik yanıta döner.
4. **Kişiye Özel Kurulum ve İzolasyon:** Her kullanıcı kendi bilgisayarında ilk açılışta (/setup) kendi yönetici kullanıcı adı/parolasını ve ayarlarını oluşturur; dağıtılan pakette geliştirici kimlik bilgileri veya kişisel veritabanı bulunmaz.

---

## Kurulum Nasıl Yapılır?

1. GitHub **Releases** (2.0.2-exe) bölümünden **AdHDF_Enterprise.exe** dosyasını bilgisayarınızda ayrı bir klasöre indirin.
2. İndirdiğiniz dosyanın bütünlüğünü **SHA-256** sağlama toplamı ile doğrulayın:
   - **Beklenen SHA-256 (2.0.2):** `82C259D2D5FD6A93BC3BBCB023193F87EA8763D1D15D14D4DF2F76C074BE1834`
3. AdHDF_Enterprise.exe dosyasına sağ tıklayıp **Yönetici olarak çalıştır** seçeneğini kullanın.
4. İlk açılışta gelen **Kurulum Sihirbazı (/setup)** üzerinden kendi **SOC Kullanıcı Adı** ve **Parolanızı** oluşturun ve başlangıç modunu seçin.

---

## Uygulama Nasıl Kullanılır?

* **SOC Paneli (/soc/dashboard):** Kurulumda belirlediğiniz kullanıcı adı ve parola ile giriş yaparak olayları, canary tetiklemelerini, tekil/engellenen IP'leri ve araç dağılımını izleyebilirsiniz.
* **AI ve Motor Ayarları (/soc/config):** **AI-Free Mode** veya **Hybrid AI** seçebilir, **Auto-Detect AI** ile yerel Ollama/LM Studio uç noktalarını tarayabilir, model adı, BLOCK_THRESHOLD, BAN_TTL_HOURS, APP_PORT ve isteğe bağlı WEBHOOK_URL ayarlarını güncelleyebilirsiniz.
* **Dış Erişim / Tünel ve Raporlama:** Dış callback adresi için CALLBACK_HOST veya **Start Public Tunnel** (cloudflared) kullanılabilir; /soc/unban, /soc/blocklist, /soc/siem/cef ve /soc/export uç noktalarıyla engelleme ve raporlama işlemleri yapılabilir.

---

## Güvenlik Notları

* Uygulamayı dış ağa veya tünele açarken bağlantıyı TLS/HTTPS ile koruyun ve paneli yetkisiz ağlara açık bırakmayın.
* .env ve dhdf_enterprise.db dosyalarını yalnızca kendi kullanıcı hesabınızın erişebileceği şekilde koruyun.
* Yalnızca yetkili olduğunuz ağ savunması, lab ve eğitim ortamlarında kullanın.
