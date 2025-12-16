import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeProvider } from "./components/ThemeProvider";
import { Header } from "./components/Header";
import { Dashboard } from "./components/Dashboard";
import RiskDashboard from "@/pages/RiskDashboard";
import Assets from "@/pages/Assets";
import Infrastructure from "@/pages/Infrastructure";
import Reports from "@/pages/Reports";
import BatchJobs from "@/pages/BatchJobs";
import Governance from "@/pages/Governance";
import Advanced from "@/pages/Advanced";
import NotFound from "@/pages/not-found";

function Router() {
  return (
    <Switch>
      <Route path="/" component={Dashboard} />
      <Route path="/risk" component={RiskDashboard} />
      <Route path="/assets" component={Assets} />
      <Route path="/infrastructure" component={Infrastructure} />
      <Route path="/reports" component={Reports} />
      <Route path="/batch" component={BatchJobs} />
      <Route path="/governance" component={Governance} />
      <Route path="/advanced" component={Advanced} />
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <TooltipProvider>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="p-6">
              <Router />
            </main>
          </div>
          <Toaster />
        </TooltipProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;
