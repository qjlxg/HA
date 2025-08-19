import geoip2.database

class GeoLite2Country:
    def __init__(self, db_path):
        self.db_path = db_path
        self.reader = None
        self._connect()

    def _connect(self):
        """内部方法，用于连接到数据库。"""
        try:
            self.reader = geoip2.database.Reader(self.db_path)
        except FileNotFoundError:
            raise

    def __enter__(self):
        """支持 'with' 语句的入口点。"""
        if not self.reader:
            self._connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """支持 'with' 语句的出口点，确保关闭连接。"""
        if self.reader:
            self.reader.close()
            self.reader = None

    def get_location(self, ip_address):
        """
        兼容 link.py 的方法，获取 IP 的国家信息。
        返回 (国家代码, 国家名称)
        """
        try:
            response = self.reader.country(ip_address)
            country_name = response.country.names.get('zh-CN', response.country.name)
            country_code = response.country.iso_code
            return country_code, country_name
        except geoip2.errors.AddressNotFoundError:
            return None, "未知"
        except Exception as e:
            print(f"查询地理位置时发生错误: {e}")
            return None, "未知"

    def get_country_by_ip(self, ip_address):
        """
        兼容 google.py 的方法，仅返回国家代码。
        """
        try:
            response = self.reader.country(ip_address)
            return response.country.iso_code
        except geoip2.errors.AddressNotFoundError:
            return "Unknown"
        except Exception:
            return "Error"
