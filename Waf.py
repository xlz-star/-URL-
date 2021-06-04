# -*- coding: utf-8 -*-
# @Time     : 2021/6/3 14:47
# @File     : Waf.py
# @Software : PyCharm

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import SVC, LinearSVC
from sklearn.model_selection import train_test_split
import urllib.parse, html, time
import pickle


class Waf:
    def __init__(self, good_queries_data, bad_queries_data):
        self.queries, self.labs = self.get_queries(good_queries_data, bad_queries_data)

        self.vectorizer = TfidfVectorizer()

        self.X = self.vectorizer.fit_transform(self.queries)

        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(self.X, self.labs, test_size=20)

        # self.svm = SVC(max_iter=500, C=0.5, kernel='rbf', degree=2)
        # self.svm = LinearSVC()
        self.svm = SVC(max_iter=2000, kernel="linear")

        begin = time.time()

        self.svm.fit(self.X_train, self.y_train)

        end = time.time()

        self.time = "{:.2f}".format(end - begin)

        self.score = self.svm.score(self.X_test, self.y_test)



    def get_runtime(self):
        return f"运行时间为：{self.time}"

    def get_score(self):
        return f"模型的得分为：{self.score}"

    def predict(self, new_queries):
        new_queries = [urllib.parse.unquote(i) for i in new_queries]
        X_predict = self.vectorizer.transform(new_queries)
        res = self.svm.predict(X_predict)
        res_list = []
        for url, lab in zip(new_queries, res):
            tmp = "正常请求" if lab == 0 else "恶意请求"
            print(f"{url} {tmp}")
            q = html.unescape(url)
            res_list.append({url: q, lab: tmp})
        # return res_list

    def save_model(self):
        with open("svm.pkl", "wb") as f:
            pickle.dump(f, self.svm)

    def load_model(self):
        with open("svm.pkl", "rb") as f:
            model = pickle.load(f)
            return model

    def get_data(self, filename):
        with open(filename, "r", encoding="utf-8") as f:
            data = f.readlines()
        return [urllib.parse.unquote(i).replace("\n", "") for i in data]

    def get_queries(self, good_queries_file, bad_queries_file):
        good_queries = self.get_data(good_queries_file)
        bad_queries = self.get_data(bad_queries_file)

        good_labs = [0 for i in range(len(good_queries))]
        bad_labs = [1 for i in range(len(bad_queries))]

        return good_queries + bad_queries, good_labs + bad_labs


if __name__ == '__main__':
    waf = Waf("goodqueries.txt", "badqueries.txt")
    print(waf.get_score())
    waf.predict(["/cgi-win/.htpasswd",
                 "/bin/cfgwiz.exe",
                 "/subscriptions.core",
                 "/cclogovs/",
                 "/epsilon-0/"])

