from selenium import webdriver

driver = webdriver.Chrome('../../../chromedriver')
driver.implicitly_wait(3)

driver.get('http://143.248.247.127:8001/wordpress/wp-login.php?redirect_to=http%3A%2F%2F143.248.247.127%3A8001%2Fwordpress%2Fwp-admin%2F&reauth=1')
print(driver.page_source)
driver.find_element_by_name('log').send_keys('test@test.test')
driver.find_element_by_name('pwd').send_keys('test')
driver.find_element_by_name("wp-submit").click()
"""driver.get('https://order.pay.naver.com/home') ## Naver 페이 들어가기
html = driver.page_source ## 페이지의 elements모두 가져오기
soup = BeautifulSoup(html, 'html.parser') ## BeautifulSoup사용하기
notices = soup.select('div.p_inr > div.p_info > a > span')"""