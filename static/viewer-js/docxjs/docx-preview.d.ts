export interface Options {
	breakPages: boolean;                    //enables page breaking on page breaks
	className: string;                      //class name/prefix for default and document style classes

	ignoreFonts: boolean;                   //disables fonts rendering
	ignoreHeight: boolean;                  //disables rendering height of page
	ignoreImageWrap: boolean;               //disables image text wrap setting
	ignoreLastRenderedPageBreak: boolean;   //disables page breaking on lastRenderedPageBreak elements
	ignoreTableWrap: boolean;               //disables table's text wrap setting
	ignoreWidth: boolean;                   //disables rendering width of page

	inWrapper: boolean;                     //enables rendering of wrapper around document content

	renderChanges: boolean;                 //enables experimental rendering of document changes (inserions/deletions)
	renderEndnotes: boolean;                //enables endnotes rendering
	renderFooters: boolean;                 //enables footers rendering
	renderFootnotes: boolean;               //enables footnotes rendering
	renderHeaders: boolean;                 //enables headers rendering

	trimXmlDeclaration: boolean;            //if true, xml declaration will be removed from xml documents before parsing
	useBase64URL: boolean;                  //if true, images, fonts, etc. will be converted to base 64 URL, otherwise URL.createObjectURL is used

	debug: boolean;                         //enables additional logging
	experimental: boolean;                  //enables experimental features (tab stops calculation)
}

export declare const defaultOptions: Options;

export declare function praseAsync(data: Blob | any, userOptions?: Partial<Options>): Promise<any>;

export declare function renderAsync(data: any, bodyContainer: HTMLElement, styleContainer?: HTMLElement, options?: Partial<Options>): Promise<any>;

export declare function renderSync(data: any, bodyContainer: HTMLElement, styleContainer?: HTMLElement, options?: Partial<Options>): Promise<any>;
