import { Composition } from 'remotion';
import { KubePoliciesDemo } from './KubePoliciesDemo';

export const RemotionRoot: React.FC = () => {
  return (
    <>
      <Composition
        id="KubePoliciesDemo"
        component={KubePoliciesDemo}
        durationInFrames={1800}
        fps={30}
        width={1920}
        height={1080}
      />
    </>
  );
};
