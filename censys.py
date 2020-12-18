import sys
import requests
import time
import json

#Здесь будет наш поисковый запрос
query = 'dana-na and 443.https.get.title: "Pulse Connect Secure"'

#Сюда вставляем свои данные для api ценсиса
UID = "юайди"
SECRET ="секрет"

#файл, в котором будут храниться результаты поиска. Его название будет равно дате и времени суток на помент запуска скрипта
output = '%s.txt' % time.strftime("%d.%m.%H.%M", time.localtime())

#Вносим страны, которые для нас в приоритете
PRIORITY_COUNTRIES =['US', 'UK', 'NL', 'DE', 'CN', 'FR', 'CA', 'JP', 'KR', 'ES']

CIS = ['UA', 'UZ', 'TJ', 'RU', 'MD', 'KG', 'KZ', 'BY', 'AZ', 'AM']
DISALLOWED = ['Medical', 'autonomous_system.description: University']

def auth():
    print('[!] Authorizing Censys API ...')
    r = requests.get("https://censys.io/api/v1/data", auth=(UID, SECRET))
    if r.status_code == 200:
        print('[+] Successfully authorized!')
        #Проверяем, стоит ли ограничение на 10 поисковых страниц
        if search(data={'page': 15, 'query': 'query', 'fields': ['ip']}).status_code == 200:
            Account = 'Enterprise'
            print('[+] Enterprise account detected!')
        else :
            Account = 'Standard'
            print('[!] Standard account detected.')
        return Account
    else :
        print('[-] Authorization failed. \n[-] Status code %s' % r.status_code)
        sys.exit()

def exclude(query, DISALLOWED):
    for i in DISALLOWED:
        query += ' and not %s' % i
    return query

def exclude_countries(query, COUNTRIES_TO_EXCLUDE):
    for i in COUNTRIES_TO_EXCLUDE:
        query += ' and not location.country_code: %s' % i
    return query

def search(data):
    #Добавляем задержку, чтобы не нарушать лимиты
    time.sleep(1)
    return requests.post("https://censys.io/api/v1/search/ipv4", data=json.dumps(data), auth=(UID, SECRET))

def retrieve(r, data):
    retVal = []
    try :
        j = r.json()
        for i in j['results']:
            retVal.append(i['ip'])
        for i in range(2, j['metadata']['pages']+1):
            if int(i) <= limit:
                print('[+] Retriving page [%s/%s]  ' % (i, j['metadata']['pages']), end = "\r")
                data['page'] = i
                nr = search(data)
                if nr.status_code == 200:
                    for i in nr.json()['results']:
                        retVal.append(i['ip'])
                else :
                    print('[-] Data retrival failed at page %s, status code %s' % (i, nr.status_code))
                    break
    except KeyError:
        pass
    return retVal

if __name__ == "__main__":
    try :
        result = []
        #Определяем тип аккаунта и его лимиты
        Account = auth()
        if Account == 'Standard' :
            limit = 10
        elif Account == 'Enterprise':
            limit = 250

       #Делаем первичную фильтрацию введённого дорка
        query = exclude_countries(query, CIS)
        query = exclude(query, DISALLOWED)
     
        data={'page': 1, 'query': query, 'fields': ['ip']}
        r = search(data)
        if r.status_code == 200 and r.json()['status'] == 'ok':
            j = r.json()
            #Если кол-во страниц в выдаче меньше или равно лимиту нашего аккаунта просто возвращаем их
            if j['metadata']['pages'] <= limit:
                print('[+] Found total %s targets in %s pages, retriving data ...' % (j['metadata']['count'], j['metadata']['pages']))
                result += retrieve(r, data)
            #Если нет, фильтруем данные
            else:
                print('[+] Found total %s targets in %s pages' % (j['metadata']['count'], j['metadata']['pages']))
                print('[!] Only the first %s result pages are available for %s Censys account\n[!] Using advanced search techniques to bypass restrictions ...' % (limit, Account))
                #Фильтруем поисковые запросы для приоритетных стран отдельно
                for i in PRIORITY_COUNTRIES:
                    print('[*] Retriving location based data for %s ' % i)
                    data['query'] = query + ' and location.country_code: %s' % i
                    nnr = search(data)
                    if nnr.json()['metadata']['pages'] <= limit:
                        result += retrieve(nnr, data)
                    else :
                        #Делаем искусственное разделение данных для обхода ограничений
                        data['query'] = query + ' and location.country_code: %s and 80.http.get.status_code: 200' % i
                        result += retrieve(search(data), data)
                        data['query'] = query + ' and location.country_code: %s and not 80.http.get.status_code: 200' % i
                        result += retrieve(search(data), data)
                #Возвращаем глобальные данные, за исключением приоритетных стран
                print('[*] Retriving global data')
                data={'page': 1, 'query': exclude_countries(query, PRIORITY_COUNTRIES), 'fields': ['ip']}
                br = search(data)
                if br.json()['metadata']['pages'] <= limit:
                    result += retrieve(br, data)
                else :
                    #Делаем искусственное разделение данных для обхода ограничений
                    data['query'] = exclude_countries(query, PRIORITY_COUNTRIES) + ' and 80.http.get.status_code: 200'
                    result += retrieve(search(data), data)
                    data['query'] = exclude_countries(query, PRIORITY_COUNTRIES) + ' and not 80.http.get.status_code: 200'
                    result += retrieve(search(data), data)
                print('[+] Successfully retrieved [%s/%s] search results' % (len(result), j['metadata']['count']))
            print('[!] Censys API data extraction finished.')
        else :
            print('[-] Request failed. \n[-] Status code %s' % r.status_code)
            sys.exit()
       #Сохраняем результаты
        with open(output, 'w') as file:
            for i in result:
                file.write(i+'\n')
    except KeyboardInterrupt:
        print('[-] User interrupdet, exitting ...')
        sys.exit()