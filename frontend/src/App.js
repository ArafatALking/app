import React, { useState, useEffect } from "react";
import "./App.css";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import axios from "axios";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./components/ui/card";
import { Button } from "./components/ui/button";
import { Input } from "./components/ui/input";
import { Alert, AlertDescription } from "./components/ui/alert";
import { Badge } from "./components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./components/ui/tabs";
import { Progress } from "./components/ui/progress";
import { AlertTriangle, Shield, Activity, BarChart3, Zap, Globe, Clock, CheckCircle } from "lucide-react";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const Dashboard = () => {
  const [url, setUrl] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState(null);
  const [results, setResults] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({});
  const [loading, setLoading] = useState(true);

  // Fetch initial data
  useEffect(() => {
    fetchResults();
    fetchAlerts();
    fetchStats();
  }, []);

  const fetchResults = async () => {
    try {
      const response = await axios.get(`${API}/results?limit=10`);
      setResults(response.data);
    } catch (error) {
      console.error("Error fetching results:", error);
    }
  };

  const fetchAlerts = async () => {
    try {
      const response = await axios.get(`${API}/alerts?limit=5`);
      setAlerts(response.data);
    } catch (error) {
      console.error("Error fetching alerts:", error);
    }
  };

  const fetchStats = async () => {
    try {
      const response = await axios.get(`${API}/stats`);
      setStats(response.data);
      setLoading(false);
    } catch (error) {
      console.error("Error fetching stats:", error);
      setLoading(false);
    }
  };

  const analyzeUrl = async () => {
    if (!url.trim()) return;
    
    setAnalyzing(true);
    setResult(null);
    
    try {
      const response = await axios.post(`${API}/analyze`, {
        url: url.trim(),
        user_id: "default_user"
      });
      
      setResult(response.data);
      await fetchResults();
      await fetchAlerts();
      await fetchStats();
    } catch (error) {
      console.error("Error analyzing URL:", error);
      setResult({
        error: true,
        message: "فشل في تحليل الرابط. يرجى المحاولة مرة أخرى."
      });
    } finally {
      setAnalyzing(false);
    }
  };

  const getRiskColor = (riskLevel) => {
    switch (riskLevel) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-green-500';
      default: return 'bg-gray-500';
    }
  };

  const getRiskBadgeColor = (riskLevel) => {
    switch (riskLevel) {
      case 'critical': return 'destructive';
      case 'high': return 'destructive';
      case 'medium': return 'default';
      case 'low': return 'secondary';
      default: return 'outline';
    }
  };

  const formatTime = (timestamp) => {
    return new Date(timestamp).toLocaleString('ar-SA');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100">
      <div className="container mx-auto p-6">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-3 bg-blue-600 rounded-2xl">
              <Shield className="h-8 w-8 text-white" />
            </div>
            <div>
              <h1 className="text-4xl font-bold text-gray-900">نظام كشف التصيد الإلكتروني</h1>
              <p className="text-lg text-gray-600 mt-1">حماية متقدمة ضد الهجمات السيبرانية باستخدام الذكاء الاصطناعي</p>
            </div>
          </div>
        </div>

        {/* Main Analysis Section */}
        <Card className="mb-8 border-0 shadow-2xl bg-white/70 backdrop-blur-sm">
          <CardHeader className="pb-4">
            <CardTitle className="flex items-center gap-2 text-xl">
              <Globe className="h-6 w-6 text-blue-600" />
              تحليل الروابط
            </CardTitle>
            <CardDescription>
              أدخل الرابط المشكوك فيه للتحقق من مستوى الخطورة
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex gap-3">
              <Input
                type="url"
                placeholder="https://example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="flex-1 h-12 text-lg border-2 focus:border-blue-500"
                dir="ltr"
              />
              <Button 
                onClick={analyzeUrl} 
                disabled={analyzing || !url.trim()}
                className="h-12 px-8 bg-blue-600 hover:bg-blue-700 text-white font-medium"
              >
                {analyzing ? (
                  <div className="flex items-center gap-2">
                    <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                    جاري التحليل...
                  </div>
                ) : (
                  <div className="flex items-center gap-2">
                    <Zap className="h-4 w-4" />
                    تحليل
                  </div>
                )}
              </Button>
            </div>

            {/* Analysis Result */}
            {result && !result.error && (
              <div className="mt-6 p-6 bg-gradient-to-r from-blue-50 to-indigo-50 rounded-2xl border border-blue-200">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    {result.is_phishing ? (
                      <AlertTriangle className="h-8 w-8 text-red-500" />
                    ) : (
                      <CheckCircle className="h-8 w-8 text-green-500" />
                    )}
                    <div>
                      <h3 className="text-2xl font-bold text-gray-900">
                        {result.is_phishing ? "تم اكتشاف تهديد!" : "الرابط آمن"}
                      </h3>
                      <p className="text-gray-600">
                        مستوى الثقة: {(result.confidence_score * 100).toFixed(1)}%
                      </p>
                    </div>
                  </div>
                  <Badge variant={getRiskBadgeColor(result.risk_level)} className="text-lg px-4 py-2">
                    {result.risk_level === 'critical' && 'حرج'}
                    {result.risk_level === 'high' && 'عالي'}
                    {result.risk_level === 'medium' && 'متوسط'}
                    {result.risk_level === 'low' && 'منخفض'}
                  </Badge>
                </div>

                <div className="mb-4">
                  <div className="flex justify-between text-sm mb-2">
                    <span>مستوى الخطورة</span>
                    <span>{(result.confidence_score * 100).toFixed(1)}%</span>
                  </div>
                  <Progress value={result.confidence_score * 100} className="h-3" />
                </div>

                {/* Analysis Details */}
                <div className="grid md:grid-cols-2 gap-4 mt-6">
                  <div className="bg-white/60 p-4 rounded-xl">
                    <h4 className="font-semibold mb-2 flex items-center gap-2">
                      <BarChart3 className="h-4 w-4" />
                      العوامل المؤثرة
                    </h4>
                    <ul className="text-sm text-gray-600 space-y-1">
                      {result.ml_prediction.contributing_factors.map((factor, idx) => (
                        <li key={idx} className="flex items-center gap-2">
                          <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
                          {factor}
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="bg-white/60 p-4 rounded-xl">
                    <h4 className="font-semibold mb-2 flex items-center gap-2">
                      <Clock className="h-4 w-4" />
                      تفاصيل التحليل
                    </h4>
                    <div className="text-sm text-gray-600 space-y-1">
                      <p>وقت المعالجة: {result.processing_time.toFixed(2)} ثانية</p>
                      <p>حالة الاستجابة: {result.analysis_details.sandbox_analysis.status_code}</p>
                      <p>عدد التحويلات: {result.analysis_details.sandbox_analysis.redirect_count}</p>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {result && result.error && (
              <Alert className="border-red-200 bg-red-50">
                <AlertTriangle className="h-4 w-4 text-red-600" />
                <AlertDescription className="text-red-700">
                  {result.message}
                </AlertDescription>
              </Alert>
            )}
          </CardContent>
        </Card>

        {/* Dashboard Tabs */}
        <Tabs defaultValue="results" className="space-y-6">
          <TabsList className="grid w-full grid-cols-3 bg-white/70 backdrop-blur-sm">
            <TabsTrigger value="results" className="flex items-center gap-2">
              <Activity className="h-4 w-4" />
              سجل التحليلات
            </TabsTrigger>
            <TabsTrigger value="alerts" className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4" />
              التنبيهات
            </TabsTrigger>
            <TabsTrigger value="stats" className="flex items-center gap-2">
              <BarChart3 className="h-4 w-4" />
              الإحصائيات
            </TabsTrigger>
          </TabsList>

          {/* Results Tab */}
          <TabsContent value="results">
            <Card className="border-0 shadow-xl bg-white/70 backdrop-blur-sm">
              <CardHeader>
                <CardTitle>آخر التحليلات</CardTitle>
                <CardDescription>سجل مفصل لجميع عمليات التحليل المنجزة</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {results.map((item, idx) => (
                    <div key={idx} className="flex items-center justify-between p-4 bg-white/60 rounded-xl border border-gray-200">
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <div className={`w-3 h-3 rounded-full ${getRiskColor(item.risk_level)}`}></div>
                          <span className="font-mono text-sm text-gray-600 break-all">
                            {item.url.length > 50 ? `${item.url.substring(0, 50)}...` : item.url}
                          </span>
                        </div>
                        <div className="flex items-center gap-4 text-sm text-gray-500">
                          <span>{formatTime(item.timestamp)}</span>
                          <span>الثقة: {(item.confidence_score * 100).toFixed(1)}%</span>
                          <span>المعالجة: {item.processing_time.toFixed(2)}ث</span>
                        </div>
                      </div>
                      <Badge variant={getRiskBadgeColor(item.risk_level)}>
                        {item.risk_level === 'critical' && 'حرج'}
                        {item.risk_level === 'high' && 'عالي'}
                        {item.risk_level === 'medium' && 'متوسط'}
                        {item.risk_level === 'low' && 'منخفض'}
                      </Badge>
                    </div>
                  ))}
                  {results.length === 0 && (
                    <div className="text-center py-8 text-gray-500">
                      لا توجد نتائج بعد. ابدأ بتحليل أول رابط!
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Alerts Tab */}
          <TabsContent value="alerts">
            <Card className="border-0 shadow-xl bg-white/70 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5 text-red-500" />
                  التنبيهات الأمنية
                </CardTitle>
                <CardDescription>تنبيهات فورية للتهديدات عالية الخطورة</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {alerts.map((alert, idx) => (
                    <Alert key={idx} className="border-red-200 bg-red-50">
                      <AlertTriangle className="h-4 w-4 text-red-600" />
                      <AlertDescription>
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="font-medium text-red-800">{alert.message}</p>
                            <p className="text-sm text-red-600 mt-1 font-mono break-all">
                              {alert.url}
                            </p>
                          </div>
                          <div className="text-right">
                            <Badge variant="destructive">{alert.risk_level}</Badge>
                            <p className="text-xs text-red-600 mt-1">
                              {formatTime(alert.timestamp)}
                            </p>
                          </div>
                        </div>
                      </AlertDescription>
                    </Alert>
                  ))}
                  {alerts.length === 0 && (
                    <div className="text-center py-8 text-gray-500">
                      لا توجد تنبيهات حالياً. النظام يعمل بشكل طبيعي!
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Stats Tab */}
          <TabsContent value="stats">
            <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
              <Card className="border-0 shadow-xl bg-white/70 backdrop-blur-sm">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-gray-600">إجمالي التحليلات</p>
                      <p className="text-3xl font-bold text-gray-900">{stats.total_analyses || 0}</p>
                    </div>
                    <div className="p-3 bg-blue-100 rounded-2xl">
                      <Activity className="h-6 w-6 text-blue-600" />
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card className="border-0 shadow-xl bg-white/70 backdrop-blur-sm">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-gray-600">التهديدات المكتشفة</p>
                      <p className="text-3xl font-bold text-red-600">{stats.phishing_detected || 0}</p>
                    </div>
                    <div className="p-3 bg-red-100 rounded-2xl">
                      <AlertTriangle className="h-6 w-6 text-red-600" />
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card className="border-0 shadow-xl bg-white/70 backdrop-blur-sm">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-gray-600">معدل الكشف</p>
                      <p className="text-3xl font-bold text-green-600">
                        {((stats.detection_rate || 0) * 100).toFixed(1)}%
                      </p>
                    </div>
                    <div className="p-3 bg-green-100 rounded-2xl">
                      <Shield className="h-6 w-6 text-green-600" />
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card className="border-0 shadow-xl bg-white/70 backdrop-blur-sm">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-gray-600">النشاط الأسبوعي</p>
                      <p className="text-3xl font-bold text-purple-600">{stats.recent_activity || 0}</p>
                    </div>
                    <div className="p-3 bg-purple-100 rounded-2xl">
                      <BarChart3 className="h-6 w-6 text-purple-600" />
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>

            <Card className="border-0 shadow-xl bg-white/70 backdrop-blur-sm">
              <CardHeader>
                <CardTitle>توزيع مستويات الخطر</CardTitle>
                <CardDescription>نظرة شاملة على أنواع التهديدات المكتشفة</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {Object.entries(stats.risk_distribution || {}).map(([level, count]) => (
                    <div key={level} className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div className={`w-4 h-4 rounded-full ${getRiskColor(level)}`}></div>
                        <span className="font-medium">
                          {level === 'critical' && 'خطر حرج'}
                          {level === 'high' && 'خطر عالي'}
                          {level === 'medium' && 'خطر متوسط'}
                          {level === 'low' && 'خطر منخفض'}
                        </span>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="text-2xl font-bold">{count}</span>
                        <div className="w-32 bg-gray-200 rounded-full h-2">
                          <div 
                            className={`h-2 rounded-full ${getRiskColor(level)}`}
                            style={{ 
                              width: `${stats.total_analyses ? (count / stats.total_analyses) * 100 : 0}%` 
                            }}
                          ></div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

function App() {
  return (
    <div className="App">
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Dashboard />} />
        </Routes>
      </BrowserRouter>
    </div>
  );
}

export default App;