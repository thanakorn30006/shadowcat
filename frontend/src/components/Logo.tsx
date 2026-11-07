import React from 'react';

interface LogoProps {
  className?: string;
  size?: 'sm' | 'md' | 'lg';
  showSubtitle?: boolean;
}

export const Logo: React.FC<LogoProps> = ({ className = '', size = 'md', showSubtitle = true }) => {
  const heights = {
    sm: 'h-8',
    md: 'h-10',
    lg: 'h-12',
  };

  return (
    <div className={`flex items-center gap-3 select-none ${className}`}>
      {/* Official ShadowCat Running Mark */}
      <img
        src="/logo-mark.png"
        alt="ShadowCat"
        className={`${heights[size]} w-auto shrink-0 object-contain drop-shadow-[0_2px_8px_rgba(0,0,0,0.8)]`}
      />

      {/* Corporate / Enterprise Typography */}
      <div className="flex flex-col">
        <div className="font-mono font-bold tracking-tight text-sm text-slate-100 flex items-center gap-1.5 leading-none">
          <span>SHADOW</span>
          <span className="text-emerald-400 font-bold">CAT</span>
        </div>
        {showSubtitle && (
          <span className="text-[10px] font-sans text-slate-400 font-medium tracking-normal mt-0.5">
            Cyber Operations Suite
          </span>
        )}
      </div>
    </div>
  );
};
