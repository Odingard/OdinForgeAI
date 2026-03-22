import { Button } from "@/components/ui/button";

interface FilterOption {
  value: string;
  label: string;
  count?: number;
}

interface FilterBarProps {
  options: FilterOption[];
  activeFilter: string;
  onFilterChange: (filter: string) => void;
}

export function FilterBar({ options, activeFilter, onFilterChange }: FilterBarProps) {
  return (
    <div className="flex items-center gap-2 flex-wrap" data-testid="filter-bar">
      {options.map((option) => (
        <Button
          key={option.value}
          variant={activeFilter === option.value ? "default" : "outline"}
          size="sm"
          onClick={() => onFilterChange(option.value)}
          className={activeFilter === option.value 
            ? "bg-gradient-to-r from-cyan-600 to-blue-600 border-0" 
            : ""}
          data-testid={`filter-${option.value}`}
        >
          {option.label}
          {option.count !== undefined && (
            <span className={`ml-1.5 px-1.5 py-0.5 text-xs rounded ${
              activeFilter === option.value 
                ? "bg-white/20" 
                : "bg-muted"
            }`}>
              {option.count}
            </span>
          )}
        </Button>
      ))}
    </div>
  );
}
