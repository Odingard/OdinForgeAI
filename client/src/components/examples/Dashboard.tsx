import { Dashboard } from "../Dashboard";
import { ThemeProvider } from "../ThemeProvider";

export default function DashboardExample() {
  return (
    <ThemeProvider>
      <div className="p-6">
        <Dashboard />
      </div>
    </ThemeProvider>
  );
}
