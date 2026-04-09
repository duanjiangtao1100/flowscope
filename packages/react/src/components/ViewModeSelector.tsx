import type { JSX } from 'react';
import { FileCode, Table2 } from 'lucide-react';
import { useLineage } from '../store';
import type { LineageViewMode } from '../types';
import { PANEL_STYLES } from '../constants';
import {
  GraphTooltip,
  GraphTooltipContent,
  GraphTooltipProvider,
  GraphTooltipTrigger,
  GraphTooltipArrow,
  GraphTooltipPortal,
} from './ui/graph-tooltip';

const VIEW_MODES: Array<{
  value: LineageViewMode;
  label: string;
  description: string;
  icon: React.ElementType;
}> = [
  {
    value: 'script',
    label: 'Script',
    description: '脚本模式-通过共享的表来展示脚本之间的关系\n\n- 作用:\n  - 节点是SQL脚本文件\n  - 边表示两个脚本之间通过共享的表产生关联\n  - 适合看：哪些脚本之间有数据依赖关系',
    icon: FileCode,
  },
  {
    value: 'table',
    label: 'Table',
    description: 'Table模式-展示表与表之间的关系\n\n- 作用:\n  - 节点是数据库表/视图/CTE\n  - 边表示表之间的直接血缘关系\n  - 适合看：数据具体是如何从一张表流向另一张表的',
    icon: Table2,
  },
];

/**
 * Segmented control for switching between different lineage view modes.
 * Displays two options: Script and Table views.
 */
export function ViewModeSelector(): JSX.Element {
  const { state, actions } = useLineage();
  const { viewMode } = state;
  const { setViewMode } = actions;

  return (
    <GraphTooltipProvider>
      <div
        className={PANEL_STYLES.selector}
        role="radiogroup"
        aria-label="Select lineage view mode"
        data-graph-panel
      >
        {VIEW_MODES.map((mode) => {
          const isActive = viewMode === mode.value;
          const Icon = mode.icon;

          return (
            <GraphTooltip key={mode.value} delayDuration={300}>
              <GraphTooltipTrigger asChild>
                <button
                  type="button"
                  role="radio"
                  aria-checked={isActive}
                  aria-label={mode.label}
                  onClick={() => setViewMode(mode.value)}
                  className={`
                    inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-full transition-all duration-200
                    ${
                      isActive
                        ? 'bg-slate-100 dark:bg-slate-700 text-slate-900 dark:text-slate-100'
                        : 'text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
                    }
                    focus-visible:outline-hidden
                  `}
                >
                  <Icon className="size-4" strokeWidth={isActive ? 2.5 : 1.5} />
                </button>
              </GraphTooltipTrigger>
              <GraphTooltipPortal>
                <GraphTooltipContent side="bottom">
                  <p>{mode.description}</p>
                  <GraphTooltipArrow />
                </GraphTooltipContent>
              </GraphTooltipPortal>
            </GraphTooltip>
          );
        })}
      </div>
    </GraphTooltipProvider>
  );
}
