async function scanURL() {
  const url = document.getElementById("urlInput").value.trim();
  const resultDiv = document.getElementById("result");

  if (!url) return (resultDiv.innerText = "رجاءً أدخل رابط.");

  resultDiv.innerText = "جارٍ الفحص...";

  const apiKey = "c4ae067d7f39b39e001beddc2f4fa5c48acee6d25b4b6a074a87c67ad2cb56ba";

  try {
    // ترميز الرابط إلى base64 URL-safe
    const encodedUrl = btoa(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // استعلام التحليل مباشرة (GET) لأن POST فحص الرابط يحتاج خطوات معقدة
    const analysisUrl = `https://www.virustotal.com/api/v3/urls/${encodedUrl}`;

    const response = await fetch(analysisUrl, {
      headers: { "x-apikey": apiKey }
    });

    if (!response.ok) {
      if (response.status === 404) {
        resultDiv.innerText = "الرابط غير موجود في قاعدة البيانات، يرجى المحاولة بعد قليل.";
      } else {
        resultDiv.innerText = "حدث خطأ في الاتصال بالخدمة.";
      }
      return;
    }

    const data = await response.json();
    const stats = data.data.attributes.last_analysis_stats;

    if (stats.malicious > 0) {
      resultDiv.innerHTML = `⚠️ الرابط **خبيث** (${stats.malicious} تحذيرات).`;
    } else {
      resultDiv.innerHTML = `✅ الرابط **آمن** حسب آخر تحليل.`;
    }

  } catch (err) {
    console.error(err);
    resultDiv.innerText = "حدث خطأ أثناء الفحص.";
  }
}
