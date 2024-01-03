# Инструкции

## Достъп до таблицата през Google Service акаунт

_На базата на [това](https://thatgurjot.com/til/google-sheets-service-account/)._

1. Създайте [Google Cloud приложение и включете Google Sheets API-то](https://developers.google.com/sheets/api/quickstart/python#enable_the_api)
2. Добавете [Service Account](https://support.google.com/a/answer/7378726?hl=en), изтеглете ключа му и запишете .json файла в `secrets_dontleak_pls/google_keys` папката
3. Споделете таблицата към формата със Service акаунта
