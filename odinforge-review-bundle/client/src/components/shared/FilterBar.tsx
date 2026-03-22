import { ReactNode } from "react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { X, Search, SlidersHorizontal } from "lucide-react";

export interface FilterOption {
  label: string;
  value: string;
}

export interface Filter {
  key: string;
  label: string;
  options: FilterOption[];
  defaultValue?: string;
}

export interface FilterBarProps {
  filters: Filter[];
  values: Record<string, string>;
  onChange: (key: string, value: string) => void;
  onReset?: () => void;
  searchValue?: string;
  onSearchChange?: (value: string) => void;
  searchPlaceholder?: string;
  showActiveCount?: boolean;
  "data-testid"?: string;
}

export function FilterBar({
  filters,
  values,
  onChange,
  onReset,
  searchValue,
  onSearchChange,
  searchPlaceholder = "Search...",
  showActiveCount = true,
  "data-testid": testId = "filter-bar",
}: FilterBarProps) {
  // Count active filters (non-default values)
  const activeFilterCount = filters.filter((filter) => {
    const currentValue = values[filter.key];
    const defaultValue = filter.defaultValue || "all";
    return currentValue && currentValue !== defaultValue;
  }).length;

  const hasActiveFilters = activeFilterCount > 0 || (searchValue && searchValue.length > 0);

  const handleReset = () => {
    if (onReset) {
      onReset();
    }
  };

  return (
    <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3" data-testid={testId}>
      {/* Search Input */}
      {onSearchChange !== undefined && (
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder={searchPlaceholder}
            value={searchValue || ""}
            onChange={(e) => onSearchChange(e.target.value)}
            className="pl-9"
            data-testid={`${testId}-search`}
          />
        </div>
      )}

      {/* Filter Dropdowns */}
      <div className="flex items-center gap-2 flex-wrap">
        {filters.map((filter) => {
          const currentValue = values[filter.key] || filter.defaultValue || "all";
          const isActive = currentValue !== (filter.defaultValue || "all");

          return (
            <div key={filter.key} className="relative">
              <Select
                value={currentValue}
                onValueChange={(value) => onChange(filter.key, value)}
              >
                <SelectTrigger
                  className={`w-[160px] ${isActive ? "border-primary" : ""}`}
                  data-testid={`${testId}-filter-${filter.key}`}
                >
                  <div className="flex items-center gap-2">
                    {isActive && (
                      <div className="h-2 w-2 rounded-full bg-primary flex-shrink-0" />
                    )}
                    <SelectValue placeholder={filter.label} />
                  </div>
                </SelectTrigger>
                <SelectContent>
                  {filter.options.map((option) => (
                    <SelectItem
                      key={option.value}
                      value={option.value}
                      data-testid={`${testId}-filter-${filter.key}-option-${option.value}`}
                    >
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          );
        })}

        {/* Active Filter Count & Reset */}
        {hasActiveFilters && (
          <div className="flex items-center gap-2">
            {showActiveCount && activeFilterCount > 0 && (
              <Badge variant="secondary" className="px-2">
                {activeFilterCount} active
              </Badge>
            )}
            {onReset && (
              <Button
                variant="ghost"
                size="sm"
                onClick={handleReset}
                data-testid={`${testId}-reset`}
              >
                <X className="h-4 w-4 mr-1" />
                Reset
              </Button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
