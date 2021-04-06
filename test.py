from detector import scan_sql_injection

url = "http://testphp.vulnweb.com/listproducts.php?cat=1"

scan_sql_injection(url)