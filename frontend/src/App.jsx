import { Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import NewScan from "./pages/NewScan";
import ScanDetail from "./pages/ScanDetail";
import Cases from "./pages/Cases";
import CaseDetail from "./pages/CaseDetail";
import History from "./pages/History";
import HowItWorks from "./pages/HowItWorks";

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/how-it-works" element={<HowItWorks />} />
        <Route path="/scan" element={<NewScan />} />
        <Route path="/scans/:scanId" element={<ScanDetail />} />
        <Route path="/cases" element={<Cases />} />
        <Route path="/cases/:caseId" element={<CaseDetail />} />
        <Route path="/history" element={<History />} />
      </Route>
    </Routes>
  );
}
